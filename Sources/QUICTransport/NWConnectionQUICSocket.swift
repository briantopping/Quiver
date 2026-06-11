/// Network.framework-backed QUIC UDP socket (Apple platforms).
///
/// swift-nio's NIOPosix raw BSD UDP socket (``NIOQUICSocket``) does not work on
/// iOS: the OS only forwards UDP that travels through a Network.framework NECP
/// flow, so a raw `bind()`+`sendto()` socket transmits **nothing** (verified
/// on-device via a packet capture — a NIOPosix client emits zero QUIC packets,
/// while the same code works on macOS). `NWConnection` registers the flow the OS
/// requires, so QUIC packets actually reach the wire.
///
/// This conformer is **connection-oriented** to a single remote — it is the
/// CLIENT socket (a client dials one server). Quiver's pure-Swift QUIC / HTTP3 /
/// WebTransport stack runs unchanged on top; only the bottom byte-pipe changes.
/// The server / listener path keeps ``NIOQUICSocket``.

#if canImport(Network)
import Foundation
import Dispatch
import Network
import NIOCore
import NIOUDPTransport
import QUICCore
import Synchronization
import os

/// TEMP on-device diagnostic — remove before upstreaming. Lets us see, via
/// `log collect`, whether the socket actually moves bytes on iOS.
private let nwqLog = os.Logger(subsystem: "com.coglative.fleet.shell", category: "nwq")

/// A ``QUICSocket`` whose datagram I/O rides on a Network.framework
/// `NWConnection` in UDP mode. See file header for why this is required on iOS.
public final class NWConnectionQUICSocket: QUICSocket, @unchecked Sendable {
    private let remote: SocketAddress
    private let connection: NWConnection
    private let queue: DispatchQueue
    private let incomingStream: AsyncStream<IncomingPacket>
    private let incomingContinuation: AsyncStream<IncomingPacket>.Continuation
    /// Guards the start() continuation so it resumes exactly once across the
    /// ready / failed / cancelled / timeout races.
    private let startResolved: Mutex<Bool>

    public var incomingPackets: AsyncStream<IncomingPacket> { incomingStream }

    /// The QUIC client does not require the local address (no path migration
    /// here); reporting nil is correct and avoids fragile endpoint parsing.
    public var localAddress: SocketAddress? {
        get async { nil }
    }

    /// - Parameter remote: the already-resolved server address. The caller has a
    ///   numeric IP (Quiver dials by IP), so we build the endpoint from the IP
    ///   literal directly and never let Network.framework re-resolve via DNS.
    public init(remote: SocketAddress) {
        self.remote = remote

        let ip = remote.ipAddress ?? "::1"
        let host: NWEndpoint.Host
        if let v6 = IPv6Address(ip) {
            host = .ipv6(v6)
        } else if let v4 = IPv4Address(ip) {
            host = .ipv4(v4)
        } else {
            host = .name(ip, nil)
        }
        let port = NWEndpoint.Port(rawValue: UInt16(remote.port ?? 443)) ?? .https

        let params = NWParameters.udp
        // Permit the connection on whatever path is up (wifi/cellular); the QUIC
        // layer owns reliability, so we don't want NW second-guessing viability.
        params.serviceClass = .responsiveData
        self.connection = NWConnection(host: host, port: port, using: params)
        self.queue = DispatchQueue(label: "quiver.nwudp")

        let (stream, continuation) = AsyncStream<IncomingPacket>.makeStream(
            bufferingPolicy: .bufferingNewest(256)
        )
        self.incomingStream = stream
        self.incomingContinuation = continuation
        self.startResolved = Mutex(false)
    }

    /// Resume the start() continuation at most once.
    private func resolveStartOnce(_ body: () -> Void) {
        let first = startResolved.withLock { resolved -> Bool in
            if resolved { return false }
            resolved = true
            return true
        }
        if first { body() }
    }

    /// Brings the connection up and begins receiving datagrams.
    ///
    /// For UDP, `.ready` fires as soon as the local NECP flow is established
    /// (there is no peer handshake at this layer) — typically within a few ms on
    /// a satisfied path. A safety timeout throws if the path never becomes
    /// usable, so a wedged `.waiting` can't hang `dial()` (which times the QUIC
    /// handshake only *after* this returns).
    public func start() async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    nwqLog.info("state=.ready")
                    self.resolveStartOnce { cont.resume() }
                case .failed(let err):
                    nwqLog.error("state=.failed \(String(describing: err), privacy: .public)")
                    self.resolveStartOnce { cont.resume(throwing: err) }
                    self.incomingContinuation.finish()
                case .cancelled:
                    self.resolveStartOnce { cont.resume(throwing: NWSocketError.cancelled) }
                    self.incomingContinuation.finish()
                case .waiting, .preparing, .setup:
                    break
                @unknown default:
                    break
                }
            }
            queue.asyncAfter(deadline: .now() + 8) { [weak self] in
                self?.resolveStartOnce { cont.resume(throwing: NWSocketError.startTimeout) }
            }
            connection.start(queue: queue)
        }
        receiveLoop()
    }

    /// Re-arms `receiveMessage` for each inbound datagram. Each UDP message is
    /// one datagram (one or more coalesced QUIC packets — Quiver's QUIC layer
    /// splits them). Loops until the connection errors, then finishes the stream.
    private func receiveLoop() {
        connection.receiveMessage { [weak self] content, _, isComplete, error in
            guard let self else { return }
            nwqLog.info("recv \(content?.count ?? 0, privacy: .public)B complete=\(isComplete, privacy: .public) err=\(error == nil ? "nil" : String(describing: error!), privacy: .public)")
            if let content, !content.isEmpty {
                var buffer = ByteBufferAllocator().buffer(capacity: content.count)
                buffer.writeBytes(content)
                self.incomingContinuation.yield(
                    IncomingPacket(
                        buffer: buffer,
                        remoteAddress: self.remote,
                        receivedAt: .now
                    )
                )
            }
            if error == nil {
                self.receiveLoop()
            } else {
                self.incomingContinuation.finish()
            }
        }
    }

    /// Sends one datagram. `address` is ignored: an `NWConnection` is bound to a
    /// single remote, which is exactly the QUIC client's one server.
    public func send(_ data: Data, to address: SocketAddress) async throws {
        nwqLog.info("send \(data.count, privacy: .public)B")
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    nwqLog.error("send err: \(String(describing: error), privacy: .public)")
                    cont.resume(throwing: error)
                } else {
                    nwqLog.info("send ok")
                    cont.resume()
                }
            })
        }
    }

    /// No `sendmmsg` equivalent on Network.framework — send sequentially. Sends
    /// here come from the actor-isolated QUIC layer, so ordering is preserved.
    public func sendBatch(_ packets: [Data], to address: SocketAddress) async throws {
        for packet in packets {
            try await send(packet, to: address)
        }
    }

    public func stop() async {
        connection.cancel()
        incomingContinuation.finish()
    }
}

/// Errors surfaced by ``NWConnectionQUICSocket`` start-up.
public enum NWSocketError: Error, Sendable {
    /// The connection was cancelled before it became ready.
    case cancelled
    /// The path never became usable within the start window.
    case startTimeout
}
#endif
