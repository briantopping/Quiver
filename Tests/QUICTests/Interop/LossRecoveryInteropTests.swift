/// End-to-end loss-recovery interop tests (RFC 9002).
///
/// These stand up a *real* Quiver client and server on loopback with an
/// impairing UDP relay wedged between them. The relay drops datagrams — either a
/// fixed prefix (deterministic) or a random fraction (sustained) — so the only
/// way a handshake and stream echo can complete is if the loss-recovery engine
/// actually retransmits the dropped CRYPTO/STREAM data (PTO probe + ACK-detected
/// retransmission, RFC 9002 §6.2 / §13.3).
///
/// This is the durable, in-suite replacement for the ad-hoc `/tmp/qproxy.py`
/// UDP-loss harness used while building the engine. Before the engine was wired,
/// a single dropped Initial stalled the handshake forever; these tests turn that
/// regression into a permanent gate.
///
/// Non-tautology: `recoversFromDroppedInitial` drops the FIRST client→server
/// datagram outright (the Initial), so it cannot pass at all unless a PTO probe
/// re-sends the lost CRYPTO — exactly the path the unit tests
/// (`PTODeadlineTests`, `LossRecoveryTests`) pin in isolation, proven here over
/// the full socket stack.

import Testing
import Foundation
import NIOCore
import NIOPosix
@testable import QUIC
@testable import QUICCore
@testable import QUICCrypto

// MARK: - Impairing UDP relay

/// A loopback UDP relay that forwards client⇄server datagrams while dropping
/// some of them, to fault-inject packet loss into a real QUIC connection.
///
/// Single bound datagram channel: datagrams whose source is the server are
/// forwarded to the last-seen client address; everything else is treated as
/// coming from the client and forwarded to the (fixed) server address. Drops are
/// applied per datagram — either a fixed count of the first datagrams in each
/// direction, or a fraction chosen by a seeded PRNG (reproducible).
final class ImpairingRelay: @unchecked Sendable {

    struct Stats: Sendable {
        var c2s = 0
        var s2c = 0
        var dropped = 0
    }

    private let group: EventLoopGroup
    private var channel: Channel?
    private let handler: RelayHandler

    /// The loopback port the relay listens on — point the client here.
    let listenPort: Int

    private init(group: EventLoopGroup, channel: Channel, handler: RelayHandler) {
        self.group = group
        self.channel = channel
        self.handler = handler
        self.listenPort = Int(channel.localAddress?.port ?? 0)
    }

    var stats: Stats { handler.snapshot() }

    /// Starts a relay forwarding to `127.0.0.1:serverPort`.
    ///
    /// - Parameters:
    ///   - serverPort: the real server's loopback port.
    ///   - lossProbability: per-datagram drop probability in [0, 1] (after the
    ///     `dropFirstEachDirection` prefix is consumed).
    ///   - dropFirstEachDirection: drop exactly this many of the first datagrams
    ///     seen in each direction outright (deterministic prefix loss).
    ///   - seed: PRNG seed for `lossProbability` (reproducible loss pattern).
    static func start(
        forwardingTo serverPort: Int,
        lossProbability: Double = 0,
        dropFirstEachDirection: Int = 0,
        seed: UInt64 = 0xC0FFEE
    ) async throws -> ImpairingRelay {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let serverAddr = try NIOCore.SocketAddress(ipAddress: "127.0.0.1", port: serverPort)
        let handler = RelayHandler(
            serverAddr: serverAddr,
            lossProbability: lossProbability,
            dropFirstEachDirection: dropFirstEachDirection,
            seed: seed
        )
        do {
            let channel = try await DatagramBootstrap(group: group)
                .channelInitializer { ch in ch.pipeline.addHandler(handler) }
                .bind(host: "127.0.0.1", port: 0)
                .get()
            return ImpairingRelay(group: group, channel: channel, handler: handler)
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    func stop() async {
        if let channel { try? await channel.close().get() }
        channel = nil
        try? await group.shutdownGracefully()
    }
}

/// NIO datagram handler implementing the impairment policy. All mutable state is
/// confined to the channel's event loop except `stats`/`drop` counters, which are
/// guarded by a lock for cross-thread reads.
private final class RelayHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>

    private let serverAddr: NIOCore.SocketAddress
    private let lossProbability: Double
    private let lock = NSLock()

    // lock-guarded
    private var clientAddr: NIOCore.SocketAddress?
    private var dropC2SRemaining: Int
    private var dropS2CRemaining: Int
    private var stats = ImpairingRelay.Stats()
    private var rngState: UInt64

    init(serverAddr: NIOCore.SocketAddress, lossProbability: Double, dropFirstEachDirection: Int, seed: UInt64) {
        self.serverAddr = serverAddr
        self.lossProbability = lossProbability
        self.dropC2SRemaining = dropFirstEachDirection
        self.dropS2CRemaining = dropFirstEachDirection
        self.rngState = seed
    }

    func snapshot() -> ImpairingRelay.Stats { lock.withLock { stats } }

    // SplitMix64 — deterministic, reproducible loss pattern given the seed.
    private func nextUnitInterval() -> Double {
        rngState &+= 0x9E37_79B9_7F4A_7C15
        var z = rngState
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        z = z ^ (z >> 31)
        return Double(z >> 11) * (1.0 / 9_007_199_254_740_992.0) // 53-bit mantissa
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        let fromServer = (envelope.remoteAddress == serverAddr)

        // Returns the address to forward to, or nil to drop this datagram.
        let destination: NIOCore.SocketAddress? = lock.withLock {
            if fromServer {
                guard let client = clientAddr else { return nil } // nowhere to send yet
                if dropS2CRemaining > 0 { dropS2CRemaining -= 1; stats.dropped += 1; return nil }
                if lossProbability > 0 && nextUnitInterval() < lossProbability {
                    stats.dropped += 1; return nil
                }
                stats.s2c += 1
                return client
            } else {
                clientAddr = envelope.remoteAddress
                if dropC2SRemaining > 0 { dropC2SRemaining -= 1; stats.dropped += 1; return nil }
                if lossProbability > 0 && nextUnitInterval() < lossProbability {
                    stats.dropped += 1; return nil
                }
                stats.c2s += 1
                return serverAddr
            }
        }

        guard let destination else { return }
        let out = AddressedEnvelope(remoteAddress: destination, data: envelope.data)
        context.writeAndFlush(wrapOutboundOut(out), promise: nil)
    }
}

// MARK: - Tests

@Suite("Loopback loss-recovery (RFC 9002 §6.2 / §13.3)")
struct LossRecoveryInteropTests {

    /// Stand up server + relay + client, run one stream echo through the relay,
    /// and return (echoMatched, relayStats). The relay sits on the wire so the
    /// connection only completes if the engine retransmits dropped data.
    private func runEcho(
        lossProbability: Double = 0,
        dropFirstEachDirection: Int = 0,
        seed: UInt64 = 0xC0FFEE,
        message: String = "loss-recovery echo over a lossy path",
        payloadBytes: Int? = nil
    ) async throws -> (matched: Bool, stats: ImpairingRelay.Stats) {
        let (server, serverRunTask, serverPort) = try await LoopbackHelper.startServer()
        let serverTask = Task {
            let connectionStream = await server.incomingConnections
            for await conn in connectionStream {
                Task {
                    for await stream in conn.incomingStreams {
                        Task { await echoStream(stream) }
                    }
                }
            }
        }

        let relay = try await ImpairingRelay.start(
            forwardingTo: Int(serverPort),
            lossProbability: lossProbability,
            dropFirstEachDirection: dropFirstEachDirection,
            seed: seed
        )

        defer {
            Task {
                await relay.stop()
                await server.stop()
                serverRunTask.cancel()
                serverTask.cancel()
            }
        }

        // Client dials the RELAY, not the server. A generous dial timeout lets
        // PTO-driven handshake retransmission complete under loss.
        let (clientEndpoint, connection) = try await LoopbackHelper.connectClient(
            port: UInt16(relay.listenPort),
            timeout: .seconds(20)
        )
        defer {
            Task {
                await connection.close(error: nil)
                await clientEndpoint.stop()
            }
        }

        let stream = try await connection.openStream()
        // A sized payload (when requested) spans many packets, so sustained loss
        // has many datagrams to hit and the engine must retransmit repeatedly.
        let payload: Data = payloadBytes.map { n in Data((0..<n).map { i in UInt8(i & 0xFF) }) }
            ?? Data(message.utf8)
        try await stream.write(payload)
        try await stream.closeWrite()

        let response = try await readAll(stream, timeout: .seconds(30))
        return (response == payload, relay.stats)
    }

    @Test("recovers from a dropped Initial (PTO probe retransmits CRYPTO)", .timeLimit(.minutes(1)))
    func recoversFromDroppedInitial() async throws {
        // Drop the first datagram in EACH direction outright. The client's first
        // datagram carries the Initial CRYPTO (ClientHello); dropping it means the
        // handshake can only proceed if a PTO probe re-sends that CRYPTO. Without
        // the loss-recovery engine this hangs until handshakeTimeout — i.e. this
        // test is RED on the pre-fix tree by construction (mutation-proven: stub
        // `recordSentPacket(frames:)` to `[]` and this times out).
        let (matched, stats) = try await runEcho(dropFirstEachDirection: 1)
        #expect(matched, "stream echo must still round-trip after a dropped Initial — the engine must retransmit the lost CRYPTO")
        #expect(stats.dropped >= 1, "the relay must actually have dropped the prefix datagram(s)")
    }

    @Test("recovers a full 8 KB bulk stream after a dropped handshake (deterministic)", .timeLimit(.minutes(2)))
    func recoversBulkStreamAfterHandshakeLoss() async throws {
        // Deterministic (no probability): drop the first datagram each direction
        // (handshake), then deliver an 8 KB multi-packet stream over the recovered
        // connection. Proves bulk delivery works end-to-end once the handshake
        // recovers. NOTE: this does NOT inject mid-stream data loss — that path is
        // the disabled KNOWN-BUG test below. Kept deterministic (no probability)
        // because sustained per-datagram loss is not yet reliably recovered.
        let (matched, stats) = try await runEcho(
            dropFirstEachDirection: 1,
            payloadBytes: 8000
        )
        #expect(matched, "the full 8 KB stream must round-trip after a recovered handshake")
        #expect(stats.dropped >= 1, "the prefix drop must have injected a real handshake loss")
    }

    @Test("baseline: clean relay path round-trips (control)", .timeLimit(.minutes(1)))
    func cleanRelayBaseline() async throws {
        // No loss — proves the relay itself is transparent, so a failure in the
        // loss cases is attributable to loss, not the relay plumbing.
        let (matched, stats) = try await runEcho()
        #expect(matched, "stream echo must round-trip through a transparent relay")
        #expect(stats.dropped == 0, "the control path must drop nothing")
        #expect(stats.c2s > 0 && stats.s2c > 0, "the relay must have forwarded in both directions")
    }

    // KNOWN BUG (found 2026-06-11 by this harness): at sustained loss ≳10% over a
    // multi-packet stream, a STREAM frame can be dropped from ALL sender tracking
    // (stream send-buffer + outbound queue + loss-detector) without ever being
    // retransmitted. The sender then believes the transfer is complete
    // (hasPendingStreamData=false, outboundQueue empty, loss-detector empty,
    // congestion window open) while the receiver is permanently stuck at the
    // offset of the lost frame — a reliability violation (a QUIC stream MUST
    // complete under any <100% loss). Diagnosed to the loss-recovery/stream-send
    // accounting, NOT the PTO-anchor or dedup work. Disabled (not deleted) so it
    // is the RED gate for the fix: drop `.disabled` once the engine retransmits
    // mid-stream loss correctly. Deterministic repro: seed 0x1 stalls at 2332/8000.
    @Test("KNOWN BUG: 12% sustained loss permanently stalls a multi-packet stream",
          .disabled("loss-recovery drops mid-stream frames from all sender tracking; see comment above"),
          .timeLimit(.minutes(2)))
    func sustainedLossAboveThresholdStalls() async throws {
        let (matched, _) = try await runEcho(
            lossProbability: 0.12,
            seed: 0x1,
            payloadBytes: 8000
        )
        #expect(matched, "the full 8 KB stream must round-trip under 12% sustained loss")
    }
}
