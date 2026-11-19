"""TCP stream reassembly and connection tracking (independent of scapy).

For each TCP connection we keep two directions (client->server, server->client).
Each direction puts segments back in sequence order, drops retransmitted bytes,
buffers out-of-order segments, and feeds the in-order byte stream to an
:class:`~fhir_dissector.http_parser.HttpParser`. Parsed requests wait in a FIFO
queue; each parsed response is paired with the oldest waiting request.
"""
from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Optional

from fhir_dissector.http_parser import DEFAULT_MAX_BODY, HTTP_METHODS, HttpMessage, HttpParser

SEQ_MOD = 1 << 32
MAX_PENDING_SEGMENTS = 1000
MAX_PENDING_BYTES = 4 * 1024 * 1024
MAX_QUEUED_REQUESTS = 1000  # unanswered requests kept per connection
DEFAULT_MAX_CONNECTIONS = 10_000  # tracked connections (memory bound)
_METHOD_PREFIXES = tuple(m.encode() + b" " for m in HTTP_METHODS)

Endpoint = tuple[str, int]


@dataclass
class Exchange:
    """A request/response pair found on one connection (either side may be missing)."""

    client: Endpoint
    server: Endpoint
    request: Optional[HttpMessage]
    response: Optional[HttpMessage]
    errors: list[str] = field(default_factory=list)


class Direction:
    """One direction of a TCP connection: sequence tracking + HTTP parser."""

    def __init__(self, parser: HttpParser) -> None:
        self.parser = parser
        self.isn: Optional[int] = None  # sequence number of byte offset 0
        self.next_off = 0  # next expected (unwrapped) byte offset
        self.pending: dict[int, bytes] = {}  # out-of-order segments by offset
        self.pending_bytes = 0
        self.fin_off: Optional[int] = None
        self.acked_off: Optional[int] = None  # highest offset the peer has ACKed
        self.gaps = 0  # number of holes skipped
        self.closed = False
        self.errors: list[str] = []

    def set_isn(self, seq: int) -> None:
        """Set the sequence number of the first data byte."""
        self.isn = seq % SEQ_MOD

    def offset(self, seq: int) -> int:
        """Map a 32-bit sequence number to an unwrapped offset near ``next_off``."""
        assert self.isn is not None
        rel = (seq - self.isn) % SEQ_MOD
        base = self.next_off - (self.next_off % SEQ_MOD)
        cand = base + rel
        # Choose the candidate closest to next_off (handles wrap-around both ways).
        if cand - self.next_off > SEQ_MOD // 2:
            cand -= SEQ_MOD
        elif self.next_off - cand > SEQ_MOD // 2:
            cand += SEQ_MOD
        return cand

    def add(self, seq: int, payload: bytes, ts: float) -> list[HttpMessage]:
        """Add one segment; return HTTP messages completed by in-order data."""
        if not payload or self.closed:
            return []
        if self.isn is None:
            self.set_isn(seq)
        off = self.offset(seq)
        end = off + len(payload)
        if end <= self.next_off:
            return []  # pure retransmission
        if off > self.next_off:
            old = self.pending.get(off)
            if old is None or len(old) < len(payload):
                self.pending_bytes += len(payload) - (len(old) if old else 0)
                self.pending[off] = payload
            if len(self.pending) > MAX_PENDING_SEGMENTS or self.pending_bytes > MAX_PENDING_BYTES:
                return self.skip_gap(ts)
            return self.check_acked_gap(ts)
        out = self._deliver(payload[self.next_off - off:], ts)
        out += self._drain(ts)
        return out

    def _deliver(self, data: bytes, ts: float) -> list[HttpMessage]:
        self.next_off += len(data)
        return self.parser.feed(data, ts)

    def _drain(self, ts: float) -> list[HttpMessage]:
        out: list[HttpMessage] = []
        while self.pending:
            off = min(self.pending)
            if off > self.next_off:
                break
            data = self.pending.pop(off)
            self.pending_bytes -= len(data)
            end = off + len(data)
            if end > self.next_off:
                out += self._deliver(data[self.next_off - off:], ts)
        return out

    def on_peer_ack(self, ack: int, ts: float) -> list[HttpMessage]:
        """Record an ACK sent by the peer for this direction's bytes."""
        if self.isn is None:
            return []
        off = self.offset(ack)
        if self.acked_off is None or off > self.acked_off:
            self.acked_off = off
        return self.check_acked_gap(ts)

    def check_acked_gap(self, ts: float) -> list[HttpMessage]:
        """If the peer ACKed bytes we never saw, they were lost by the capture: skip them."""
        if self.pending and self.acked_off is not None and min(self.pending) <= self.acked_off:
            return self.skip_gap(ts)
        return []

    def skip_gap(self, ts: float) -> list[HttpMessage]:
        """Jump over missing bytes to the lowest buffered segment and resync the parser."""
        if not self.pending:
            return []
        self.gaps += 1
        was_resyncing = self.parser.resync
        self.next_off = min(self.pending)
        out = self.parser.reset(ts)
        # A partial message already carries the "gap" error itself. Otherwise flag the
        # next exchange, unless we were already skipping bytes after an earlier gap.
        if not out and not was_resyncing:
            self.errors.append("gap")
        return out + self._drain(ts)

    def fin_reached(self) -> bool:
        return self.fin_off is not None and self.next_off >= self.fin_off

    def close(self, ts: float) -> list[HttpMessage]:
        """Flush any buffered data (skipping holes) and close the parser."""
        if self.closed:
            return []
        out: list[HttpMessage] = []
        while self.pending:
            out += self.skip_gap(ts)
        out += self.parser.close(ts)
        self.closed = True
        return out


class Connection:
    """A tracked TCP connection with its two directions and request queue."""

    def __init__(self, client: Endpoint, server: Endpoint, max_body: int, ts: float) -> None:
        self.client = client
        self.server = server
        self.requests: deque[HttpMessage] = deque()
        self.c2s = Direction(HttpParser("request", max_body=max_body))
        self.s2c = Direction(HttpParser("response", request_method=self._pending_method,
                                        max_body=max_body))
        self.last_ts = ts
        self.rst = False
        self.client_syn_seen = False

    def _pending_method(self) -> Optional[str]:
        return self.requests[0].method if self.requests else None

    def direction(self, src: Endpoint) -> Direction:
        return self.c2s if src == self.client else self.s2c

    def handle(self, src: Endpoint, flags: str, seq: int, payload: bytes, ts: float,
               ack: Optional[int] = None) -> list[Exchange]:
        """Process one segment of this connection."""
        self.last_ts = ts
        d = self.direction(src)
        other = self.s2c if d is self.c2s else self.c2s
        if "S" in flags:
            d.set_isn(seq + 1)  # SYN consumes one sequence number
            if src == self.client and "A" not in flags:
                self.client_syn_seen = True
        out: list[Exchange] = []
        if ack is not None and "A" in flags and "S" not in flags:
            out += self._messages(other, other.on_peer_ack(ack, ts))
        if payload:
            out += self._messages(d, d.add(seq, payload, ts))
        if "F" in flags and d.isn is not None:
            d.fin_off = d.offset(seq) + len(payload)
        if d.fin_reached() and not d.closed:
            out += self._messages(d, d.close(ts))
        if "R" in flags:
            self.rst = True
        return out

    def _messages(self, d: Direction, msgs: list[HttpMessage]) -> list[Exchange]:
        out: list[Exchange] = []
        for m in msgs:
            if d is self.c2s:
                self.requests.append(m)
                if len(self.requests) > MAX_QUEUED_REQUESTS:  # server never answers: bound memory
                    out.append(Exchange(self.client, self.server, self.requests.popleft(), None,
                                        ["request-queue-overflow"]))
            else:
                req = self.requests.popleft() if self.requests else None
                errors = self._take_errors()
                if req is None:
                    errors.append("response-without-request")
                out.append(Exchange(self.client, self.server, req, m, errors))
        return out

    def _take_errors(self) -> list[str]:
        errs = self.c2s.errors + self.s2c.errors
        self.c2s.errors, self.s2c.errors = [], []
        return errs

    @property
    def finished(self) -> bool:
        return self.rst or (self.c2s.closed and self.s2c.closed)

    def close(self, ts: float) -> list[Exchange]:
        """Close both directions and emit leftover requests with ``response=None``."""
        out = self._messages(self.c2s, self.c2s.close(ts))
        out += self._messages(self.s2c, self.s2c.close(ts))
        while self.requests:
            out.append(Exchange(self.client, self.server, self.requests.popleft(), None,
                                self._take_errors()))
        return out


def _guess_client(src: Endpoint, dst: Endpoint, flags: str, payload: bytes) -> Optional[Endpoint]:
    """Decide which endpoint is the client, or None if we cannot tell yet."""
    if "S" in flags:
        return dst if "A" in flags else src
    if not payload:
        return None
    if payload.startswith(_METHOD_PREFIXES):
        return src
    if payload.startswith(b"HTTP/1."):
        return dst
    # Mid-message capture: fall back to "the lower port is the server".
    return dst if dst[1] < src[1] else src


class TcpReassembler:
    """Tracks many TCP connections and returns HTTP exchanges.

    Args:
        max_body: per-message stored body cap (bytes).
        idle_timeout: drop connections idle for this many seconds (``None`` = never).
        check_every: how often (in packets) to look for idle connections.
        max_connections: upper bound on tracked connections; when reached, the least
            recently active connection is closed (its exchanges get the error ``evicted``).
    """

    def __init__(self, max_body: int = DEFAULT_MAX_BODY, idle_timeout: Optional[float] = 120.0,
                 check_every: int = 1000, max_connections: int = DEFAULT_MAX_CONNECTIONS) -> None:
        self.max_body = max_body
        self.idle_timeout = idle_timeout
        self.check_every = check_every
        self.max_connections = max(1, max_connections)
        # Ordered by last activity (oldest first), so eviction is O(1).
        self.conns: OrderedDict[tuple[Endpoint, Endpoint], Connection] = OrderedDict()
        self.packets = 0
        self.connections_seen = 0
        self.evicted = 0

    def _lookup(self, src: Endpoint, dst: Endpoint) -> Optional[Connection]:
        return self.conns.get((src, dst)) or self.conns.get((dst, src))

    def _remove(self, conn: Connection) -> None:
        self.conns.pop((conn.client, conn.server), None)

    def process(self, ts: float, src: str, sport: int, dst: str, dport: int,
                flags: str, seq: int, payload: bytes, ack: Optional[int] = None) -> list[Exchange]:
        """Process one TCP segment. ``flags`` uses scapy letters (S, A, F, R, P).

        ``ack`` is optional. When given, it lets us detect bytes that the peer received
        but the capture missed, and skip such holes immediately instead of waiting.
        """
        self.packets += 1
        a, b = (src, sport), (dst, dport)
        out: list[Exchange] = []
        conn = self._lookup(a, b)
        # A new SYN on a known 4-tuple means the old connection ended (port reuse).
        if conn is not None and "S" in flags and "A" not in flags and conn.client_syn_seen \
                and conn.c2s.isn is not None and conn.c2s.isn != (seq + 1) % SEQ_MOD:
            out += conn.close(ts)
            self._remove(conn)
            conn = None
        if conn is None:
            client = _guess_client(a, b, flags, payload)
            if client is None:
                return out
            server = b if client == a else a
            while len(self.conns) >= self.max_connections:
                out += self._evict_oldest(ts)
            conn = Connection(client, server, self.max_body, ts)
            self.conns[(client, server)] = conn
            self.connections_seen += 1
        else:
            self.conns.move_to_end((conn.client, conn.server))
        out += conn.handle(a, flags, seq, payload, ts, ack)
        if conn.finished:
            out += conn.close(ts)
            self._remove(conn)
        if self.idle_timeout is not None and self.packets % self.check_every == 0:
            out += self.expire(ts)
        return out

    def _evict_oldest(self, ts: float) -> list[Exchange]:
        _, conn = self.conns.popitem(last=False)
        self.evicted += 1
        out = conn.close(ts)
        for ex in out:
            ex.errors.append("evicted")
        return out

    def expire(self, now: float) -> list[Exchange]:
        """Close connections idle for longer than ``idle_timeout``."""
        if self.idle_timeout is None:
            return []
        out: list[Exchange] = []
        for conn in list(self.conns.values()):
            if now - conn.last_ts > self.idle_timeout:
                out += conn.close(now)
                self._remove(conn)
        return out

    def flush(self, ts: Optional[float] = None) -> list[Exchange]:
        """Close every open connection (end of capture / shutdown)."""
        out: list[Exchange] = []
        for conn in list(self.conns.values()):
            out += conn.close(conn.last_ts if ts is None else ts)
            self._remove(conn)
        return out
