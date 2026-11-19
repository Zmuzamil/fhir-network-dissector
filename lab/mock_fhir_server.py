"""Tiny in-memory FHIR R4 server for the lab (fallback when Docker/HAPI is unavailable).

Standard library only. It supports exactly what ``lab/gen_traffic.py`` uses:

* ``GET /fhir/metadata`` (CapabilityStatement)
* create / read / vread / update / delete / history on any resource type
* search by type (``GET Type?...`` and ``POST Type/_search``) with simple params
* ``POST /fhir`` with a transaction or batch Bundle
* ``GET /fhir/Patient/{id}/$everything``
* JSON, and minimal XML when ``Accept: application/fhir+xml`` or ``_format=xml``
* 404 / 410 with an OperationOutcome
* a non-FHIR HTML page at ``/``

Usage::

    python lab/mock_fhir_server.py --port 8081
    # base URL: http://localhost:8081/fhir
"""
from __future__ import annotations

import argparse
import copy
import json
import socket
import threading
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qsl, urlsplit

FHIR_JSON = "application/fhir+json;charset=UTF-8"
FHIR_XML = "application/fhir+xml;charset=UTF-8"
FHIR_NS = "http://hl7.org/fhir"
BASE = "/fhir"

HTML_PAGE = b"""<!doctype html>
<html><head><title>Mock FHIR lab server</title></head>
<body><h1>Mock FHIR lab server</h1><p>The FHIR API lives at <a href="/fhir/metadata">/fhir</a>.</p></body></html>
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def operation_outcome(severity: str, code: str, diagnostics: str) -> dict[str, Any]:
    """Build a minimal OperationOutcome resource."""
    return {
        "resourceType": "OperationOutcome",
        "issue": [{"severity": severity, "code": code, "diagnostics": diagnostics}],
    }


class Store:
    """Thread-safe in-memory, versioned resource store.

    ``data[type][id]`` is a list of versions; ``None`` marks a deletion (tombstone).
    """

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.data: dict[str, dict[str, list[dict[str, Any] | None]]] = {}
        self.next_id = 1

    def new_id(self) -> str:
        with self.lock:
            rid = str(self.next_id)
            self.next_id += 1
            return rid

    def _add_version(self, rtype: str, rid: str, resource: dict[str, Any]) -> dict[str, Any]:
        versions = self.data.setdefault(rtype, {}).setdefault(rid, [])
        res = copy.deepcopy(resource)
        res["resourceType"] = rtype
        res["id"] = rid
        res["meta"] = {"versionId": str(len(versions) + 1), "lastUpdated": _now()}
        versions.append(res)
        return copy.deepcopy(res)

    def create(self, rtype: str, resource: dict[str, Any], rid: str | None = None) -> dict[str, Any]:
        with self.lock:
            return self._add_version(rtype, rid or self.new_id(), resource)

    def update(self, rtype: str, rid: str, resource: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Return (stored resource, created?)."""
        with self.lock:
            created = rid not in self.data.get(rtype, {})
            return self._add_version(rtype, rid, resource), created

    def delete(self, rtype: str, rid: str) -> bool:
        with self.lock:
            versions = self.data.get(rtype, {}).get(rid)
            if not versions or versions[-1] is None:
                return False
            versions.append(None)
            return True

    def current(self, rtype: str, rid: str) -> tuple[int, dict[str, Any] | None]:
        """Return (status, resource): 200 found, 404 never existed, 410 deleted."""
        with self.lock:
            versions = self.data.get(rtype, {}).get(rid)
            if not versions:
                return 404, None
            if versions[-1] is None:
                return 410, None
            return 200, copy.deepcopy(versions[-1])

    def history(self, rtype: str, rid: str) -> list[dict[str, Any]] | None:
        with self.lock:
            versions = self.data.get(rtype, {}).get(rid)
            if not versions:
                return None
            return [copy.deepcopy(v) for v in reversed(versions) if v is not None]

    def vread(self, rtype: str, rid: str, vid: str) -> dict[str, Any] | None:
        with self.lock:
            for v in self.data.get(rtype, {}).get(rid, []):
                if v is not None and v["meta"]["versionId"] == vid:
                    return copy.deepcopy(v)
            return None

    def all_current(self, rtype: str | None = None) -> list[dict[str, Any]]:
        with self.lock:
            out: list[dict[str, Any]] = []
            for t, by_id in self.data.items():
                if rtype and t != rtype:
                    continue
                for versions in by_id.values():
                    if versions and versions[-1] is not None:
                        out.append(copy.deepcopy(versions[-1]))
            return out


def _matches(res: dict[str, Any], name: str, value: str) -> bool:
    """Very small subset of FHIR search semantics (enough for the lab)."""
    value_l = value.lower()
    if name == "_id":
        return res.get("id") == value
    if name in ("family", "given", "name"):
        for hn in res.get("name", []) or []:
            fam = str(hn.get("family", "")).lower()
            given = [str(g).lower() for g in hn.get("given", []) or []]
            if name in ("family", "name") and fam.startswith(value_l):
                return True
            if name in ("given", "name") and any(g.startswith(value_l) for g in given):
                return True
        return False
    if name in ("subject", "patient"):
        ref = str((res.get("subject") or {}).get("reference", ""))
        return ref == value or ref.endswith("/" + value) or ref == "Patient/" + value
    return True  # unknown params are ignored, like many real servers


def search(store: Store, rtype: str, params: list[tuple[str, str]]) -> list[dict[str, Any]]:
    results = store.all_current(rtype)
    count: int | None = None
    for name, value in params:
        if name == "_count":
            try:
                count = int(value)
            except ValueError:
                pass
            continue
        if name.startswith("_") and name != "_id":
            continue
        results = [r for r in results if _matches(r, name, value)]
    return results[:count] if count is not None else results


def bundle(btype: str, resources: list[dict[str, Any]], base_url: str) -> dict[str, Any]:
    return {
        "resourceType": "Bundle",
        "id": str(uuid.uuid4()),
        "meta": {"lastUpdated": _now()},
        "type": btype,
        "total": len(resources),
        "entry": [
            {"fullUrl": f"{base_url}/{r['resourceType']}/{r['id']}", "resource": r}
            for r in resources
        ],
    }


# ---------------------------------------------------------------- XML output
def _fill_xml(el: ET.Element, obj: dict[str, Any]) -> None:
    for key, val in obj.items():
        if key == "resourceType":
            continue
        for item in val if isinstance(val, list) else [val]:
            if isinstance(item, dict):
                child = ET.SubElement(el, key)
                if "resourceType" in item:  # nested resource (Bundle.entry.resource)
                    _fill_xml(ET.SubElement(child, item["resourceType"]), item)
                else:
                    _fill_xml(child, item)
            else:
                if isinstance(item, bool):
                    text = "true" if item else "false"
                else:
                    text = str(item)
                ET.SubElement(el, key, value=text)


def to_xml(resource: dict[str, Any]) -> bytes:
    """Minimal JSON -> FHIR XML conversion (good enough for the lab)."""
    root = ET.Element(resource.get("resourceType", "Unknown"), xmlns=FHIR_NS)
    _fill_xml(root, resource)
    return b'<?xml version="1.0" encoding="UTF-8"?>' + ET.tostring(root, encoding="utf-8")


# ---------------------------------------------------------------- handler
class FhirHandler(BaseHTTPRequestHandler):
    """Request handler; ``self.server.store`` holds the data."""

    protocol_version = "HTTP/1.1"  # keep-alive
    server_version = "MockFHIR/0.1"

    # -- helpers ---------------------------------------------------------
    @property
    def store(self) -> Store:
        return self.server.store  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:  # quieter, no bodies
        if not getattr(self.server, "quiet", False):
            super().log_message(fmt, *args)

    def _base_url(self) -> str:
        host = self.headers.get("Host", "localhost")
        return f"http://{host}{BASE}"

    def _wants_xml(self, query: list[tuple[str, str]]) -> bool:
        fmt = dict(query).get("_format", "")
        if fmt:
            return "xml" in fmt
        return "fhir+xml" in self.headers.get("Accept", "")

    def _send(
        self,
        status: int,
        body: dict[str, Any] | None,
        query: list[tuple[str, str]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        if body is None:
            payload, ctype = b"", None
        elif self._wants_xml(query or []):
            payload, ctype = to_xml(body), FHIR_XML
        else:
            payload, ctype = json.dumps(body, indent=2).encode("utf-8"), FHIR_JSON
        self.send_response(status)
        if ctype:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if payload and self.command != "HEAD":
            self.wfile.write(payload)

    def _send_raw(self, status: int, ctype: str, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(length) if length > 0 else b""

    def _read_json(self) -> dict[str, Any] | None:
        try:
            data = json.loads(self._read_body() or b"null")
            return data if isinstance(data, dict) else None
        except (ValueError, UnicodeDecodeError):
            return None

    def _not_found(self, query: list[tuple[str, str]], what: str) -> None:
        self._send(404, operation_outcome("error", "not-found", f"{what} is not known"), query)

    def _resource_headers(self, res: dict[str, Any]) -> dict[str, str]:
        vid = res["meta"]["versionId"]
        return {
            "ETag": f'W/"{vid}"',
            "Last-Modified": res["meta"]["lastUpdated"],
            "Location": f"{self._base_url()}/{res['resourceType']}/{res['id']}/_history/{vid}",
        }

    # -- routing ---------------------------------------------------------
    def _route(self) -> None:
        url = urlsplit(self.path)
        query = parse_qsl(url.query, keep_blank_values=True)
        path = url.path
        if path in ("/", "/index.html"):
            body = self._read_body()  # drain
            del body
            self._send_raw(200, "text/html; charset=UTF-8", HTML_PAGE)
            return
        if path != BASE and not path.startswith(BASE + "/"):
            self._read_body()
            self._send_raw(404, "text/plain; charset=UTF-8", b"Not found\n")
            return
        segs = [s for s in path[len(BASE):].split("/") if s]
        m = self.command
        try:
            self._dispatch(m, segs, query)
        except Exception as exc:  # never crash the lab server
            self._send(500, operation_outcome("fatal", "exception", repr(exc)), query)

    def _dispatch(self, m: str, segs: list[str], query: list[tuple[str, str]]) -> None:
        n = len(segs)
        if n == 0 and m == "POST":
            return self._bundle(query)
        if n == 1 and segs[0] == "metadata" and m == "GET":
            return self._send(200, self._capabilities(), query)
        if n == 0:
            return self._not_found(query, "System-level search")
        rtype = segs[0]
        if n == 1 and m == "GET":
            res = search(self.store, rtype, query)
            return self._send(200, bundle("searchset", res, self._base_url()), query)
        if n == 1 and m == "POST":
            body = self._read_json()
            if body is None:
                return self._send(400, operation_outcome("error", "invalid", "Body is not JSON"), query)
            res = self.store.create(rtype, body)
            return self._send(201, res, query, self._resource_headers(res))
        if n == 2 and segs[1] == "_search" and m == "POST":
            form = parse_qsl(self._read_body().decode("utf-8", "replace"), keep_blank_values=True)
            res = search(self.store, rtype, query + form)
            return self._send(200, bundle("searchset", res, self._base_url()), query)
        rid = segs[1]
        if n == 2 and m == "GET":
            status, res = self.store.current(rtype, rid)
            if status == 200 and res is not None:
                return self._send(200, res, query, self._resource_headers(res))
            if status == 410:
                return self._send(410, operation_outcome("error", "deleted", f"{rtype}/{rid} was deleted"), query)
            return self._not_found(query, f"{rtype}/{rid}")
        if n == 2 and m == "PUT":
            body = self._read_json()
            if body is None:
                return self._send(400, operation_outcome("error", "invalid", "Body is not JSON"), query)
            res, created = self.store.update(rtype, rid, body)
            return self._send(201 if created else 200, res, query, self._resource_headers(res))
        if n == 2 and m == "DELETE":
            self.store.delete(rtype, rid)
            return self._send(200, operation_outcome("information", "informational", "Delete done"), query)
        if n == 3 and segs[2] == "_history" and m == "GET":
            hist = self.store.history(rtype, rid)
            if hist is None:
                return self._not_found(query, f"{rtype}/{rid}")
            return self._send(200, bundle("history", hist, self._base_url()), query)
        if n == 4 and segs[2] == "_history" and m == "GET":
            res = self.store.vread(rtype, rid, segs[3])
            if res is None:
                return self._not_found(query, f"{rtype}/{rid}/_history/{segs[3]}")
            return self._send(200, res, query, self._resource_headers(res))
        if n == 3 and segs[2] == "$everything" and m == "GET" and rtype == "Patient":
            status, patient = self.store.current("Patient", rid)
            if patient is None:
                return self._not_found(query, f"Patient/{rid}")
            related = [
                r for r in self.store.all_current()
                if str((r.get("subject") or {}).get("reference", "")) == f"Patient/{rid}"
            ]
            return self._send(200, bundle("searchset", [patient] + related, self._base_url()), query)
        self._read_body()
        return self._send(400, operation_outcome("error", "not-supported", "Interaction not supported"), query)

    def _capabilities(self) -> dict[str, Any]:
        types = sorted({"Patient", "Observation", *self.store.data.keys()})
        return {
            "resourceType": "CapabilityStatement",
            "status": "active",
            "date": _now(),
            "kind": "instance",
            "software": {"name": "MockFHIR", "version": "0.1"},
            "fhirVersion": "4.0.1",
            "format": ["application/fhir+json", "application/fhir+xml"],
            "rest": [{"mode": "server", "resource": [{"type": t} for t in types]}],
        }

    def _bundle(self, query: list[tuple[str, str]]) -> None:
        body = self._read_json()
        if not body or body.get("resourceType") != "Bundle" or body.get("type") not in ("transaction", "batch"):
            return self._send(400, operation_outcome("error", "invalid", "Expected transaction or batch Bundle"), query)
        btype = body["type"]
        entries = body.get("entry", []) or []
        # Pass 1: assign ids for POST entries so urn:uuid references can be rewritten.
        id_map: dict[str, str] = {}
        planned: list[str | None] = []
        for e in entries:
            req = e.get("request", {}) or {}
            if req.get("method") == "POST" and isinstance(e.get("resource"), dict):
                new_id = self.store.new_id()
                planned.append(new_id)
                if e.get("fullUrl"):
                    id_map[e["fullUrl"]] = f"{e['resource'].get('resourceType')}/{new_id}"
            else:
                planned.append(None)

        def rewrite(obj: Any) -> Any:
            if isinstance(obj, dict):
                return {k: (id_map.get(v, v) if k == "reference" and isinstance(v, str) else rewrite(v))
                        for k, v in obj.items()}
            if isinstance(obj, list):
                return [rewrite(x) for x in obj]
            return obj

        out_entries: list[dict[str, Any]] = []
        for e, new_id in zip(entries, planned):
            req = e.get("request", {}) or {}
            method, url = req.get("method", ""), str(req.get("url", ""))
            if method == "POST" and new_id:
                res = self.store.create(url.split("?")[0], rewrite(e["resource"]), new_id)
                out_entries.append({"response": {
                    "status": "201 Created",
                    "location": f"{res['resourceType']}/{res['id']}/_history/1",
                }})
            elif method == "GET":
                u = urlsplit(url)
                parts = [p for p in u.path.split("/") if p]
                if len(parts) == 2:
                    status, res = self.store.current(parts[0], parts[1])
                    ent: dict[str, Any] = {"response": {"status": str(status)}}
                    if res:
                        ent["resource"] = res
                    out_entries.append(ent)
                elif len(parts) == 1:
                    found = search(self.store, parts[0], parse_qsl(u.query))
                    out_entries.append({
                        "resource": bundle("searchset", found, self._base_url()),
                        "response": {"status": "200 OK"},
                    })
                else:
                    out_entries.append({"response": {"status": "400 Bad Request"}})
            else:
                out_entries.append({"response": {"status": "400 Bad Request"}})
        result = {
            "resourceType": "Bundle",
            "id": str(uuid.uuid4()),
            "type": f"{btype}-response",
            "entry": out_entries,
        }
        self._send(200, result, query)

    do_GET = _route
    do_POST = _route
    do_PUT = _route
    do_DELETE = _route
    do_PATCH = _route
    do_HEAD = _route


class DualStackServer(ThreadingHTTPServer):
    """Listen on IPv6 and IPv4 at once, so ``localhost`` works whichever it resolves to."""

    address_family = socket.AF_INET6
    daemon_threads = True

    def server_bind(self) -> None:
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except (AttributeError, OSError):
            pass
        super().server_bind()


def make_server(port: int = 8081, quiet: bool = False) -> ThreadingHTTPServer:
    """Create (but do not start) a mock server on all local addresses."""
    try:
        server: ThreadingHTTPServer = DualStackServer(("::", port), FhirHandler)
    except OSError:
        server = ThreadingHTTPServer(("0.0.0.0", port), FhirHandler)
        server.daemon_threads = True
    server.store = Store()  # type: ignore[attr-defined]
    server.quiet = quiet  # type: ignore[attr-defined]
    return server


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--quiet", action="store_true", help="do not log each request")
    args = ap.parse_args(argv)
    server = make_server(args.port, args.quiet)
    print(f"Mock FHIR server on http://localhost:{args.port}{BASE}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
