import Testing
import Foundation
@testable import QUICRecovery
@testable import QUICCore

/// RFC 9002 §6.2.1 — the Probe Timeout (PTO) is armed relative to the time the
/// *last ack-eliciting packet was sent*:
///
///     PTO deadline = time_of_last_ack_eliciting_packet + PTO_period
///
/// A defect that anchors the deadline to `now` instead makes it a perpetually-
/// receding horizon: the timer loop computes "PTO from now", sleeps, then
/// recomputes "PTO from now" again — so the deadline never elapses, the probe
/// never fires, and a lost Initial (or any lost packet on a quiet path) is
/// never retransmitted. The connection then dies on the *first* lost packet.
///
/// (Found 2026-06-11 via UDP loss injection against the WebTransportDemo: a
/// dropped Initial produced zero retransmissions until handshakeTimeout.)
@Suite("PTO deadline anchoring (RFC 9002 §6.2.1)")
struct PTODeadlineTests {

    @Test("PTO deadline anchors to the last ack-eliciting send time, not now")
    func ptoAnchorsToSendTimeNotNow() {
        let mgr = PacketNumberSpaceManager()

        // The client sends one ack-eliciting, in-flight Initial at t0
        // (a real 1200-byte QUIC Initial).
        let t0 = ContinuousClock.now
        mgr.onPacketSent(SentPacket(
            packetNumber: 0,
            encryptionLevel: .initial,
            timeSent: t0,
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200))

        // Query the PTO deadline well past one PTO period (~1s for the default
        // initial RTT). t0 + 10s is far beyond t0 + PTO.
        let later = t0 + .seconds(10)
        let deadline = mgr.nextPTODeadline(now: later)

        // RFC 9002 §6.2.1: deadline == t0 + PTO, which by `later` has long
        // elapsed → a probe is overdue. The bug returns `later + PTO` (always
        // in the future) → the probe never fires.
        #expect(deadline <= later,
            "PTO must anchor to the last ack-eliciting send time (t0 + PTO), not now + PTO")
    }
}
