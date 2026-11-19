"""Build synthetic TCP/HTTP conversations with scapy (for tests).

``build_conversation`` returns a list of scapy packets: handshake, the given
request/response byte strings split into small segments, and a FIN exchange.
Options simulate real-world capture problems:

* ``shuffle``   - reorder segments inside each burst (out-of-order delivery)
* ``duplicate`` - add retransmissions, including overlapping ones
* ``handshake=False`` - start mid-stream (capture began after the SYN)
* ``ipv6``      - use IPv6 instead of IPv4
"""
from __future__ import annotations

import random
from pathlib import Path
from typing import Iterator, Sequence

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

Endpoint = tuple[str, int]


class _Side:
    def __init__(self, ep: Endpoint, isn: int) -> None:
        self.ep = ep
        self.seq = isn


def _segments(data: bytes, size: int) -> list[tuple[int, bytes]]:
    return [(i, data[i:i + size]) for i in range(0, len(data), size)]


def build_conversation(
    exchanges: Sequence[tuple[bytes, bytes]],
    *,
    client: Endpoint = ("10.0.0.1", 50000),
    server: Endpoint = ("10.0.0.2", 8080),
    ipv6: bool = False,
    segment_size: int = 40,
    handshake: bool = True,
    shuffle: bool = False,
    duplicate: bool = False,
    fin: bool = True,
    client_isn: int = 1000,
    server_isn: int = 900_000,
    start_ts: float = 1_700_000_000.0,
    seed: int = 1,
) -> list[Packet]:
    """Build packets for one TCP connection carrying ``exchanges`` (request, response)."""
    if ipv6 and client[0].startswith("10."):
        client, server = ("fd00::1", client[1]), ("fd00::2", server[1])
    rng = random.Random(seed)
    c, s = _Side(client, client_isn), _Side(server, server_isn)
    pkts: list[Packet] = []
    clock = [start_ts]

    def mk(src: _Side, dst: _Side, flags: str, seq: int, ack: int, payload: bytes = b"") -> Packet:
        ip = (IPv6(src=src.ep[0], dst=dst.ep[0]) if ipv6 else IP(src=src.ep[0], dst=dst.ep[0]))
        p = Ether() / ip / TCP(sport=src.ep[1], dport=dst.ep[1], flags=flags,
                               seq=seq % (1 << 32), ack=ack % (1 << 32))
        if payload:
            p = p / Raw(load=payload)
        clock[0] += 0.001
        p.time = clock[0]
        return p

    if handshake:
        pkts.append(mk(c, s, "S", c.seq, 0))
        pkts.append(mk(s, c, "SA", s.seq, c.seq + 1))
        pkts.append(mk(c, s, "A", c.seq + 1, s.seq + 1))
    c.seq += 1
    s.seq += 1

    def burst(src: _Side, dst: _Side, data: bytes) -> None:
        segs = _segments(data, segment_size)
        packets = [mk(src, dst, "PA", src.seq + off, dst.seq, chunk) for off, chunk in segs]
        if duplicate and segs:
            extra = []
            for _ in range(max(1, len(segs) // 3)):
                off, chunk = rng.choice(segs)
                extra.append(mk(src, dst, "PA", src.seq + off, dst.seq, chunk))
            if len(segs) >= 2:  # overlapping retransmission spanning two segments
                i = rng.randrange(len(segs) - 1)
                off = segs[i][0] + len(segs[i][1]) // 2
                span = data[off:segs[i + 1][0] + len(segs[i + 1][1])]
                extra.append(mk(src, dst, "PA", src.seq + off, dst.seq, span))
            for e in extra:
                packets.insert(rng.randrange(1, len(packets) + 1), e)
        if shuffle:
            rng.shuffle(packets)
        pkts.extend(packets)
        src.seq += len(data)
        pkts.append(mk(dst, src, "A", dst.seq, src.seq))

    for request, response in exchanges:
        if request:
            burst(c, s, request)
        if response:
            burst(s, c, response)

    if fin:
        pkts.append(mk(c, s, "FA", c.seq, s.seq))
        pkts.append(mk(s, c, "FA", s.seq, c.seq + 1))
        pkts.append(mk(c, s, "A", c.seq + 1, s.seq + 1))
    return pkts


def tcp_tuples(packets: Sequence[Packet]) -> Iterator[tuple[float, str, int, str, int, str, int, bytes, int]]:
    """Yield ``(ts, src, sport, dst, dport, flags, seq, payload, ack)`` for each TCP packet."""
    for p in packets:
        if TCP not in p:
            continue
        ip = p[IP] if IP in p else p[IPv6]
        t = p[TCP]
        yield (float(p.time), ip.src, t.sport, ip.dst, t.dport, str(t.flags), t.seq, bytes(t.payload), t.ack)


def write_pcap(path: str | Path, packets: Sequence[Packet]) -> Path:
    """Write packets to a PCAP file and return its path."""
    path = Path(path)
    wrpcap(str(path), list(packets))
    return path


# ----------------------------------------------------------- HTTP helpers
def http_request(method: str, target: str, headers: dict[str, str] | None = None,
                 body: bytes = b"", host: str = "localhost:8080") -> bytes:
    """Build raw HTTP/1.1 request bytes (adds Host and Content-Length)."""
    h = {"Host": host, **(headers or {})}
    if body and "Content-Length" not in h and "Transfer-Encoding" not in h:
        h["Content-Length"] = str(len(body))
    head = f"{method} {target} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items())
    return head.encode("latin-1") + b"\r\n" + body


def http_response(status: int, headers: dict[str, str] | None = None, body: bytes = b"",
                  reason: str = "OK", chunked: bool = False, chunk_size: int = 7) -> bytes:
    """Build raw HTTP/1.1 response bytes (Content-Length or chunked)."""
    h = dict(headers or {})
    if chunked:
        h["Transfer-Encoding"] = "chunked"
        payload = b"".join(
            f"{len(body[i:i + chunk_size]):x}\r\n".encode() + body[i:i + chunk_size] + b"\r\n"
            for i in range(0, len(body), chunk_size)
        ) + b"0\r\n\r\n"
    else:
        h.setdefault("Content-Length", str(len(body)))
        payload = body
    head = f"HTTP/1.1 {status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items())
    return head.encode("latin-1") + b"\r\n" + payload
