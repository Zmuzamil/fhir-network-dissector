"""Incremental HTTP/1.1 parser (one instance per direction of a TCP connection).

The parser is a small state machine::

    HEADERS --> LENGTH(n) | CHUNKED | UNTIL_CLOSE | NONE --> HEADERS ...

It never raises on bad input: problems are recorded in ``HttpMessage.errors`` and the
parser re-synchronises on the next line that looks like a request/status line.
"""
from __future__ import annotations

import re
import zlib
from dataclasses import dataclass, field
from typing import Callable, Optional

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT")

_REQUEST_LINE = re.compile(rb"^([A-Z]{3,10}) (\S+) HTTP/(\d\.\d)$")
_STATUS_LINE = re.compile(rb"^HTTP/(\d\.\d) (\d{3})(?: (.*))?$")
# Used to resync after garbage or a gap. Not anchored to a line start: after a gap the
# next message usually begins right after the lost body bytes, with no newline before it.
_START_LINE_ANYWHERE = re.compile(
    rb"((?:" + b"|".join(m.encode() for m in HTTP_METHODS) + rb") [!-~]+ HTTP/1\.[01]\r?\n"
    rb"|HTTP/1\.[01] \d{3}[^\n]*\n)"
)

DEFAULT_MAX_HEADER = 64 * 1024
DEFAULT_MAX_BODY = 10_000_000
_MAX_CHUNK_LINE = 1024

# States
HEADERS = "HEADERS"
LENGTH = "LENGTH"
CHUNK_SIZE = "CHUNK_SIZE"
CHUNK_DATA = "CHUNK_DATA"
CHUNK_CRLF = "CHUNK_CRLF"
TRAILERS = "TRAILERS"
UNTIL_CLOSE = "UNTIL_CLOSE"
DEAD = "DEAD"  # after 101 Switching Protocols: stop parsing


@dataclass
class HttpMessage:
    """One parsed HTTP request or response.

    ``body`` is the decoded body (de-chunked and decompressed, capped at ``max_body``).
    ``body_size`` is the body length on the wire after de-chunking (before decompression).
    """

    kind: str  # "request" | "response"
    method: Optional[str] = None
    target: Optional[str] = None
    status: Optional[int] = None
    reason: Optional[str] = None
    version: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    body_size: int = 0
    truncated: bool = False
    errors: list[str] = field(default_factory=list)
    ts: float = 0.0
    end_ts: float = 0.0

    def header(self, name: str, default: str = "") -> str:
        """Case-insensitive header lookup."""
        return self.headers.get(name.lower(), default)


def _decompress(data: bytes, encoding: str, limit: int) -> tuple[bytes, Optional[str]]:
    """Undo gzip/deflate. Returns (body, error). On failure returns the raw body."""
    enc = encoding.strip().lower()
    if enc in ("", "identity"):
        return data, None
    if enc not in ("gzip", "x-gzip", "deflate"):
        return data, f"unsupported-content-encoding:{enc}"
    # wbits=47 auto-detects gzip and zlib headers; raw deflate (-15) as a fallback.
    for wbits in (47, -15):
        try:
            d = zlib.decompressobj(wbits=wbits)
            out = d.decompress(data, limit) if limit > 0 else d.decompress(data)
            return out, None
        except zlib.error:
            continue
    return data, "decompress-failed"


class HttpParser:
    """Incremental HTTP/1.1 parser for one direction.

    Args:
        kind: ``"request"`` (client->server bytes) or ``"response"`` (server->client).
        request_method: for responses, a callback returning the method of the request
            this response answers (needed for HEAD responses, which have no body).
        max_body: maximum number of body bytes stored per message.
        max_header: maximum size of a header block.
    """

    def __init__(
        self,
        kind: str,
        request_method: Optional[Callable[[], Optional[str]]] = None,
        max_body: int = DEFAULT_MAX_BODY,
        max_header: int = DEFAULT_MAX_HEADER,
    ) -> None:
        if kind not in ("request", "response"):
            raise ValueError("kind must be 'request' or 'response'")
        self.kind = kind
        self.request_method = request_method
        self.max_body = max_body
        self.max_header = max_header
        self.buf = bytearray()
        self.state = HEADERS
        self.msg: Optional[HttpMessage] = None
        self.remaining = 0  # bytes left in LENGTH / CHUNK_DATA
        self.resync = False  # discarding bytes until a valid start line
        self.pending_errors: list[str] = []  # attached to the next emitted message
        self._body = bytearray()
        self._start_ts: Optional[float] = None
        self._raw_size = 0

    # ------------------------------------------------------------------ public
    def feed(self, data: bytes, ts: float = 0.0) -> list[HttpMessage]:
        """Add bytes (in stream order) and return every message completed so far."""
        if self.state == DEAD or not data:
            return []
        if self._start_ts is None and self.state == HEADERS and not self.buf.strip():
            self._start_ts = ts
        self.buf += data
        out: list[HttpMessage] = []
        try:
            self._run(ts, out)
        except Exception as exc:  # defensive: never propagate
            self._error(f"parser-exception:{type(exc).__name__}")
            out += self.reset(ts)
        return out

    def close(self, ts: float = 0.0) -> list[HttpMessage]:
        """End of stream: complete an until-close body, or flag a truncated message."""
        out: list[HttpMessage] = []
        if self.msg is not None and self.state != DEAD:
            if self.state == UNTIL_CLOSE:
                self._consume_body(bytes(self.buf))
                self.buf.clear()
                out.append(self._finish(ts))
            elif self.state != HEADERS:
                self.msg.truncated = True
                self.msg.errors.append("incomplete-message-at-close")
                out.append(self._finish(ts))
        elif self.state == HEADERS and self.buf.strip() and not self.resync:
            self._error("incomplete-headers-at-close")
        self.buf.clear()
        self.state = DEAD
        return out

    def reset(self, ts: float = 0.0) -> list[HttpMessage]:
        """Handle a gap in the stream: resync on the next start line.

        A message whose headers were already parsed is returned as a partial message
        (``truncated=True``, error ``gap``), so request/response pairing stays correct.
        """
        out: list[HttpMessage] = []
        if self.msg is not None and self.state not in (HEADERS, DEAD):
            self.msg.truncated = True
            self.msg.errors.append("gap")
            out.append(self._finish(ts))
        if self.state == DEAD:
            return out
        self.buf.clear()
        self.state = HEADERS
        self.msg = None
        self._body = bytearray()
        self._start_ts = None
        self.resync = True
        return out

    # ----------------------------------------------------------------- engine
    def _error(self, err: str) -> None:
        if self.msg is not None:
            self.msg.errors.append(err)
        else:
            self.pending_errors.append(err)

    def _run(self, ts: float, out: list[HttpMessage]) -> None:
        while True:
            before = (self.state, len(self.buf))
            if self.state == HEADERS:
                if not self._parse_headers(ts, out):
                    return
            elif self.state == LENGTH:
                take = min(self.remaining, len(self.buf))
                self._consume_body(bytes(self.buf[:take]))
                del self.buf[:take]
                self.remaining -= take
                if self.remaining > 0:
                    return
                out.append(self._finish(ts))
            elif self.state == CHUNK_SIZE:
                if not self._parse_chunk_size(ts, out):
                    return
            elif self.state == CHUNK_DATA:
                take = min(self.remaining, len(self.buf))
                self._consume_body(bytes(self.buf[:take]))
                del self.buf[:take]
                self.remaining -= take
                if self.remaining > 0:
                    return
                self.state = CHUNK_CRLF
            elif self.state == CHUNK_CRLF:
                if self.buf.startswith(b"\r\n"):
                    del self.buf[:2]
                elif self.buf.startswith(b"\n"):
                    del self.buf[:1]
                elif len(self.buf) < 2 and self.buf in (b"", b"\r"):
                    return
                else:
                    self._error("chunk-missing-crlf")
                self.state = CHUNK_SIZE
            elif self.state == TRAILERS:
                if not self._parse_trailers(ts, out):
                    return
            elif self.state == UNTIL_CLOSE:
                self._consume_body(bytes(self.buf))
                self.buf.clear()
                return
            else:  # DEAD
                self.buf.clear()
                return
            if (self.state, len(self.buf)) == before and not self.buf:
                return

    # -- header block --------------------------------------------------------
    def _do_resync(self) -> bool:
        """Discard bytes up to the next plausible start line. True if one was found."""
        m = _START_LINE_ANYWHERE.search(self.buf)
        if not m:
            keep = 64  # a start line may be split across feeds
            if len(self.buf) > keep:
                del self.buf[:-keep]
            return False
        del self.buf[: m.start(1)]
        self.resync = False
        return True

    def _parse_headers(self, ts: float, out: list[HttpMessage]) -> bool:
        # Skip blank lines between messages.
        while self.buf[:2] == b"\r\n" or self.buf[:1] == b"\n":
            del self.buf[: 2 if self.buf[:2] == b"\r\n" else 1]
        if not self.buf:
            self._start_ts = None
            return False
        if self.resync and not self._do_resync():
            return False
        if self._start_ts is None:
            self._start_ts = ts
        # Validate the first line as soon as it is complete (fast garbage detection).
        nl = self.buf.find(b"\n")
        if nl >= 0:
            first = bytes(self.buf[:nl]).rstrip(b"\r")
            if not self._valid_start_line(first):
                self._error("bad-start-line")
                del self.buf[: nl + 1]
                self.resync = True
                return True
        elif len(self.buf) > self.max_header:
            self._error("header-overflow")
            self.buf.clear()
            self.resync = True
            return False
        end = self.buf.find(b"\r\n\r\n")
        sep = 4
        alt = self.buf.find(b"\n\n")
        if alt >= 0 and (end < 0 or alt < end):
            end, sep = alt, 2
        if end < 0:
            if len(self.buf) > self.max_header:
                self._error("header-overflow")
                self.buf.clear()
                self.resync = True
            return False
        if end > self.max_header:
            self._error("header-overflow")
            del self.buf[: end + sep]
            self.resync = True
            return True
        block = bytes(self.buf[:end])
        del self.buf[: end + sep]
        self._start_message(block, ts, out)
        return True

    def _valid_start_line(self, line: bytes) -> bool:
        if self.kind == "request":
            return bool(_REQUEST_LINE.match(line))
        return bool(_STATUS_LINE.match(line))

    def _start_message(self, block: bytes, ts: float, out: list[HttpMessage]) -> None:
        lines = block.replace(b"\r\n", b"\n").split(b"\n")
        first = lines[0]
        msg = HttpMessage(kind=self.kind, ts=self._start_ts if self._start_ts is not None else ts)
        msg.errors.extend(self.pending_errors)
        self.pending_errors = []
        if self.kind == "request":
            m = _REQUEST_LINE.match(first)
            assert m is not None  # validated earlier
            msg.method = m.group(1).decode("ascii")
            msg.target = m.group(2).decode("latin-1")
            msg.version = "HTTP/" + m.group(3).decode("ascii")
        else:
            m = _STATUS_LINE.match(first)
            assert m is not None
            msg.version = "HTTP/" + m.group(1).decode("ascii")
            msg.status = int(m.group(2))
            msg.reason = (m.group(3) or b"").decode("latin-1").strip()
        for raw in lines[1:]:
            if not raw:
                continue
            if raw[:1] in (b" ", b"\t"):  # obsolete line folding
                msg.errors.append("obs-fold-header")
                continue
            name, colon, value = raw.partition(b":")
            if not colon or not name.strip():
                msg.errors.append("malformed-header-line")
                continue
            key = name.strip().decode("latin-1").lower()
            val = value.strip().decode("latin-1")
            msg.headers[key] = f"{msg.headers[key]}, {val}" if key in msg.headers else val
        self.msg = msg
        self._body = bytearray()
        self._raw_size = 0
        self._choose_body_mode(ts, out)

    def _content_length(self, msg: HttpMessage) -> Optional[int]:
        raw = msg.headers.get("content-length")
        if raw is None:
            return None
        values = {v.strip() for v in raw.split(",")}
        if len(values) > 1:
            msg.errors.append("conflicting-content-length")
        try:
            n = int(sorted(values)[0])
            if n < 0:
                raise ValueError
            return n
        except ValueError:
            msg.errors.append("bad-content-length")
            return None

    def _choose_body_mode(self, ts: float, out: list[HttpMessage]) -> None:
        msg = self.msg
        assert msg is not None
        chunked = "chunked" in msg.headers.get("transfer-encoding", "").lower()
        if self.kind == "request":
            if chunked:
                self.state = CHUNK_SIZE
                return
            n = self._content_length(msg)
            if n:
                self.state, self.remaining = LENGTH, n
                return
            out.append(self._finish(ts))
            return
        status = msg.status or 0
        if 100 <= status < 200:
            if status == 101:
                out.append(self._finish(ts))
                self.state = DEAD
                return
            # Interim response (e.g. 100 Continue): not emitted, keep parsing.
            self.msg = None
            self._start_ts = None
            self.state = HEADERS
            return
        method = None
        if self.request_method is not None:
            try:
                method = self.request_method()
            except Exception:
                method = None
        if method == "HEAD" or status in (204, 304):
            out.append(self._finish(ts))
            return
        if chunked:
            self.state = CHUNK_SIZE
            return
        n = self._content_length(msg)
        if n is not None:
            if n == 0:
                out.append(self._finish(ts))
            else:
                self.state, self.remaining = LENGTH, n
            return
        self.state = UNTIL_CLOSE

    # -- chunked -------------------------------------------------------------
    def _parse_chunk_size(self, ts: float, out: list[HttpMessage]) -> bool:
        nl = self.buf.find(b"\n")
        if nl < 0:
            if len(self.buf) > _MAX_CHUNK_LINE:
                self._abort_message("bad-chunk-size", ts, out)
                return True
            return False
        line = bytes(self.buf[:nl]).rstrip(b"\r").split(b";", 1)[0].strip()
        del self.buf[: nl + 1]
        try:
            size = int(line, 16)
            if size < 0:
                raise ValueError
        except ValueError:
            self._abort_message("bad-chunk-size", ts, out)
            return True
        if size == 0:
            self.state = TRAILERS
        else:
            self.state, self.remaining = CHUNK_DATA, size
        return True

    def _parse_trailers(self, ts: float, out: list[HttpMessage]) -> bool:
        if self.buf.startswith(b"\r\n"):
            del self.buf[:2]
        elif self.buf.startswith(b"\n"):
            del self.buf[:1]
        else:
            end = self.buf.find(b"\r\n\r\n")
            sep = 4
            if end < 0:
                end, sep = self.buf.find(b"\n\n"), 2
            if end < 0:
                if len(self.buf) > self.max_header:
                    self._abort_message("trailer-overflow", ts, out)
                    return True
                return False
            del self.buf[: end + sep]  # trailers are ignored
        out.append(self._finish(ts))
        return True

    def _abort_message(self, err: str, ts: float, out: list[HttpMessage]) -> None:
        """Emit the current message as broken and resync."""
        if self.msg is not None:
            self.msg.errors.append(err)
            self.msg.truncated = True
            out.append(self._finish(ts))
        self.resync = True

    # -- body ----------------------------------------------------------------
    def _consume_body(self, data: bytes) -> None:
        if not data or self.msg is None:
            return
        self._raw_size += len(data)
        room = self.max_body - len(self._body)
        if room > 0:
            self._body += data[:room]
        if len(data) > room:
            self.msg.truncated = True

    def _finish(self, ts: float) -> HttpMessage:
        msg = self.msg
        assert msg is not None
        msg.body_size = self._raw_size
        body = bytes(self._body)
        enc = msg.headers.get("content-encoding", "")
        if body and enc:
            body, err = _decompress(body, enc, self.max_body)
            if err:
                msg.errors.append(err)
        msg.body = body
        msg.end_ts = ts
        self.msg = None
        self._body = bytearray()
        self._raw_size = 0
        self._start_ts = None
        if self.state != DEAD:
            self.state = HEADERS
        return msg
