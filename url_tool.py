#!/usr/bin/env python3
"""Parse, normalize and sanity-check URLs."""
from __future__ import annotations

import argparse
import json
import re
import sys
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

DEFAULT_PORTS = {"http": 80, "https": 443}
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def components(url: str) -> dict:
    parsed = urlparse(url)
    return {
        "scheme": parsed.scheme,
        "username": parsed.username,
        "password": "***" if parsed.password else None,
        "host": parsed.hostname,
        "port": parsed.port,
        "path": parsed.path,
        "query": dict(parse_qsl(parsed.query, keep_blank_values=True)),
        "fragment": parsed.fragment,
    }


def normalize(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if port is not None and DEFAULT_PORTS.get(scheme) == port:
        port = None
    netloc = host if port is None else f"{host}:{port}"
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    path = parsed.path or "/"
    return urlunparse((scheme, netloc, path, "", query, parsed.fragment))


def check(url: str):
    parsed = urlparse(url)
    notes = []
    if parsed.password:
        notes.append({"issue": "credentials-in-url", "severity": "medium",
                      "detail": "URL contains a password; it will end up in logs."})
    if parsed.scheme not in ("http", "https"):
        notes.append({"issue": "unusual-scheme", "severity": "high",
                      "detail": f"scheme {parsed.scheme!r} is not http(s)."})
    if not parsed.hostname:
        notes.append({"issue": "missing-host", "severity": "high",
                      "detail": "URL has no host component."})
    elif IP_RE.match(parsed.hostname):
        notes.append({"issue": "ip-literal", "severity": "low",
                      "detail": "host is an IP address; certificates may not match."})
    if parsed.port and parsed.port not in DEFAULT_PORTS.values():
        notes.append({"issue": "non-standard-port", "severity": "low",
                      "detail": f"port {parsed.port} is not the scheme default."})
    return notes


def render(url: str, data: dict) -> str:
    lines = [f"url: {url}"]
    for key in ("scheme", "username", "password", "host", "port", "path", "fragment"):
        lines.append(f"  {key:<9} {data[key] if data[key] is not None else '-'}")
    lines.append("  query")
    for key, value in data["query"].items():
        lines.append(f"    {key} = {value}")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="URL inspector")
    parser.add_argument("url")
    parser.add_argument("--normalize", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    data = components(args.url)
    notes = check(args.url) if args.check else []
    payload = {"url": args.url, "components": data,
               "normalized": normalize(args.url), "notes": notes}
    if args.json:
        print(json.dumps(payload, indent=2))
    elif args.normalize:
        print(payload["normalized"])
    else:
        print(render(args.url, data))
        for note in notes:
            print(f"  [{note['severity']}] {note['issue']}: {note['detail']}")
    return 1 if any(n["severity"] == "high" for n in notes) else 0


if __name__ == "__main__":
    raise SystemExit(main())
