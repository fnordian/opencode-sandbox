#!/usr/bin/env python3
"""Lightweight HTTP/HTTPS proxy with dynamic domain allowlisting via Unix Socket.

Usage:
  http-proxy.py <socket-path> [--db-dir <dir>] [--profile <name>...] [PATTERN...]

The allow-list is composed of two parts:
  1. Baseline — positional PATTERN args (set once at startup, immutable at runtime).
  2. Profiles — JSON files in --db-dir named <profile>.json, watched for changes.

Each PATTERN is a regex string (compiled with re.IGNORECASE) of one of these forms:
  - (?:.*\\.)?domain\\.com   → suffix-match (domain.com + any subdomain)
  - domain\\.com             → exact-match (only domain.com)
  - any other regex        → regex-match (linear scan fallback)

Profiles are automatically reloaded when the file changes (polling every 1.5s).
On reload error, the previous list is preserved.
"""

import argparse
import asyncio
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import h11


# ---------------------------------------------------------------------------
# AllowList — two-tier compiled allow-list (suffix set + regex fallback)
# ---------------------------------------------------------------------------

# Meta-patterns for classifying a pattern string at compile time.
# Suffix form:  (?:.*\.)?<literal-with-escaped-dots>       → e.g. (?:.*\.)?github\.com
# Exact form:   <literal-with-escaped-dots>                 → e.g. 127\.0\.0\.1
# Anything else → regular expression (linear-scan fallback).

# NOTE: pattern strings contain escaped dots (\.), so the meta-regexes
# must match literal backslash + dot sequences, not just dots.
# Example pattern:  (?:.*\.)?github\.com
#                    ^^               ^^
#                    prefix           domain with \.

_SUFFIX_RE = re.compile(
    r"^\(\?:\.\*\\\.\)\?((?:[A-Za-z0-9-]+\\\.)*[A-Za-z0-9-]+)$"
)
_EXACT_RE = re.compile(
    r"^((?:[A-Za-z0-9-]+\\\.)*[A-Za-z0-9-]+)$"
)


def _classify(pattern: str):
    """Classify a pattern string into one of three buckets.

    Returns:
      ("exact", literal)  — exact host match (O(1) set lookup)
      ("suffix", literal) — suffix match, subdomains allowed (O(m) walk)
      ("regex", None)     — irregular pattern, linear scan fallback
    """
    m = _SUFFIX_RE.match(pattern)
    if m:
        return "suffix", m.group(1).replace("\\.", ".")
    m = _EXACT_RE.match(pattern)
    if m:
        return "exact", m.group(1).replace("\\.", ".")
    return "regex", None


@dataclass(frozen=True)
class AllowList:
    """Immutable compiled allow-list.

    Three buckets for efficient matching:
      - exact  : frozenset[str] — literal hostnames (O(1))
      - suffix : frozenset[str] — domain names with subdomain wildcard (O(m) suffix walk)
      - regex  : tuple[re.Pattern, ...] — irregular patterns (linear scan)
    """

    exact: frozenset[str] = frozenset()
    suffix: frozenset[str] = frozenset()
    regex: tuple[re.Pattern, ...] = ()

    # ── factory ──────────────────────────────────────────────────────────

    @staticmethod
    def compile(patterns: list[str]) -> "AllowList":
        """Compile a list of pattern strings into an AllowList."""
        exact: set[str] = set()
        suffix: set[str] = set()
        regex: list[re.Pattern] = []
        for p in patterns:
            kind, literal = _classify(p)
            if kind == "exact":
                exact.add(literal.lower())
            elif kind == "suffix":
                suffix.add(literal.lower())
            else:
                regex.append(re.compile(p, re.IGNORECASE))
        return AllowList(
            exact=frozenset(exact),
            suffix=frozenset(suffix),
            regex=tuple(regex),
        )

    @staticmethod
    def empty() -> "AllowList":
        return AllowList()

    # ── merge ────────────────────────────────────────────────────────────

    def merge(self, other: "AllowList") -> "AllowList":
        """Return a new AllowList that is the union of self and other."""
        if not other:
            return self
        if not self:
            return other
        return AllowList(
            exact=self.exact | other.exact,
            suffix=self.suffix | other.suffix,
            regex=self.regex + other.regex,
        )

    # ── lookup ───────────────────────────────────────────────────────────

    def allows(self, host: str) -> bool:
        """Check if *host* is permitted by this allow-list."""
        if not host:
            return False
        h = host.lower()
        # O(1) exact match
        if h in self.exact:
            return True
        # O(m) suffix walk where m = number of dot-labels (typically 2-5)
        parts = h.split(".")
        for i in range(len(parts)):
            if ".".join(parts[i:]) in self.suffix:
                return True
        # O(k) regex fallback where k = number of irregular patterns (typically <10)
        return any(p.fullmatch(h) for p in self.regex)

    # ── inspection ───────────────────────────────────────────────────────

    def __len__(self) -> int:
        return len(self.exact) + len(self.suffix) + len(self.regex)

    def __bool__(self) -> bool:
        return len(self) > 0


# ---------------------------------------------------------------------------
# Profile loading & file watcher
# ---------------------------------------------------------------------------

class ProfileError(Exception):
    """Raised when a profile file cannot be loaded."""

def _load_profile_patterns(db_dir: str, names: list[str]) -> list[str]:
    """Read profile JSON files and return a flat list of pattern strings.

    Raises ProfileError on any file-level error so callers (especially
    the runtime watcher) can preserve the previous state.
    """
    patterns: list[str] = []
    for name in names:
        path = os.path.join(db_dir, f"{name}.json")
        try:
            with open(path) as f:
                data = json.load(f)
        except FileNotFoundError:
            raise ProfileError(f"profile not found: {path}")
        except json.JSONDecodeError as e:
            raise ProfileError(f"bad JSON in {path}: {e}")

        if isinstance(data, dict):
            patterns.extend(data.get("patterns", []))
        elif isinstance(data, list):
            patterns.extend(data)
        else:
            raise ProfileError(
                f"unexpected structure in {path}: expected "
                f"{{'patterns': [...]}} or [...]"
            )
    return patterns


async def _watch_profiles(
    wl: "Allowlists",
    db_dir: str,
    names: list[str],
    *,
    interval: float = 1.5,
) -> None:
    """Background task: poll profile file mtimes, reload on change."""
    if not names:
        return

    mtimes: dict[str, int] = {}
    while True:
        await asyncio.sleep(interval)
        changed = False
        for name in names:
            path = os.path.join(db_dir, f"{name}.json")
            try:
                m = os.stat(path).st_mtime_ns
            except OSError:
                continue
            if mtimes.get(path) != m:
                mtimes[path] = m
                changed = True
        if changed:
            try:
                raw = _load_profile_patterns(db_dir, names)
                new_al = AllowList.compile(raw)
                wl.swap_active(new_al)
            except ProfileError as e:
                print(
                    f"[http-proxy] reload failed, keeping previous list: {e}",
                    file=sys.stderr,
                )


# ---------------------------------------------------------------------------
# Allowlists holder — baseline (CLI) + active (profiles), atomically swapped
# ---------------------------------------------------------------------------

class Allowlists:
    """Holds baseline + active AllowLists, merged for single-reference lookup."""

    def __init__(self):
        self._baseline: AllowList = AllowList.empty()
        self._active: AllowList = AllowList.empty()

    def setup(self, baseline: AllowList, initial_active: AllowList) -> None:
        self._baseline = baseline
        self._active = baseline.merge(initial_active)

    def swap_active(self, new_active: AllowList) -> int:
        self._active = self._baseline.merge(new_active)
        return len(self._active)

    def allows(self, host: str) -> bool:
        return self._active.allows(host)

    @property
    def total(self) -> int:
        return len(self._active)


# ---------------------------------------------------------------------------
# HTTP proxy helpers
# ---------------------------------------------------------------------------

HOP_BY_HOP = frozenset({
    b"proxy-connection", b"connection", b"keep-alive",
    b"transfer-encoding", b"upgrade",
})


async def pipe(reader, writer):
    """Raw bidirectional pipe for CONNECT tunnels."""
    try:
        while data := await reader.read(4096):
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    writer.close()


def _extract_host_port(headers: h11.Headers) -> tuple[str, int]:
    """Return (host, port) from the Host header."""
    for name, value in headers:
        if name.lower() == b"host":
            h = value.decode()
            if ":" in h:
                host, port_s = h.rsplit(":", 1)
                return host, int(port_s)
            return h, 80
    return "", 80


def _rewrite_target(target: bytes) -> bytes:
    """Rewrite an absolute-URI target to origin form (path only)."""
    t = target.decode()
    if t.startswith(("http://", "https://")):
        parsed = urlparse(t)
        new_path = parsed.path or "/"
        if parsed.query:
            new_path += "?" + parsed.query
        return new_path.encode()
    return target


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

async def handle(reader, writer):
    client_conn = h11.Connection(our_role=h11.SERVER)
    tunnel_mode = False
    try:
        while True:
            # ════════════════════════════════════════════════════════════════
            # Phase 1 — Read one complete request from the proxy client
            # ════════════════════════════════════════════════════════════════
            req_event = None
            body = bytearray()
            eom_received = False

            while not eom_received:
                event = client_conn.next_event()
                if event is h11.NEED_DATA:
                    data = await asyncio.wait_for(reader.read(65536), timeout=60.0)
                    if not data:
                        return
                    client_conn.receive_data(data)
                    continue
                if event is h11.PAUSED:
                    client_conn.start_next_cycle()
                    continue
                if isinstance(event, h11.ConnectionClosed):
                    return
                if isinstance(event, h11.Request):
                    req_event = event
                elif isinstance(event, h11.Data):
                    body.extend(event.data)
                elif isinstance(event, h11.EndOfMessage):
                    eom_received = True

            # ════════════════════════════════════════════════════════════════
            # Phase 2 — CONNECT tunnel
            # ════════════════════════════════════════════════════════════════
            if req_event.method == b"CONNECT":
                raw_target = req_event.target.decode()
                if ":" in raw_target:
                    host, port_s = raw_target.rsplit(":", 1)
                    port = int(port_s)
                else:
                    host, port = raw_target, 443

                if not ALLOWLISTS.allows(host):
                    writer.write(client_conn.send(
                        h11.Response(status_code=403, headers=[(b"connection", b"close")])))
                    writer.write(client_conn.send(h11.EndOfMessage()))
                    await writer.drain()
                    return

                writer.write(client_conn.send(
                    h11.Response(status_code=200, headers=[])))
                await writer.drain()

                remote_r, remote_w = await asyncio.open_connection(host, port)
                t1 = asyncio.create_task(pipe(reader, remote_w))
                t2 = asyncio.create_task(pipe(remote_r, writer))
                tunnel_mode = True
                done, pending = await asyncio.wait(
                    [t1, t2], return_when=asyncio.FIRST_COMPLETED
                )
                for t in pending:
                    t.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                return

            # ════════════════════════════════════════════════════════════════
            # Phase 3 — HTTP: parse host, check allowlist, rewrite URI
            # ════════════════════════════════════════════════════════════════
            host, port = _extract_host_port(req_event.headers)

            if not ALLOWLISTS.allows(host):
                writer.write(client_conn.send(
                    h11.Response(status_code=403, headers=[(b"connection", b"close")])))
                writer.write(client_conn.send(h11.EndOfMessage()))
                await writer.drain()
                return

            new_target = _rewrite_target(req_event.target)

            origin_headers = [
                (n, v) for n, v in req_event.headers if n.lower() not in HOP_BY_HOP
            ]

            # ════════════════════════════════════════════════════════════════
            # Phase 4 — Forward request to origin
            # ════════════════════════════════════════════════════════════════
            origin_conn = h11.Connection(our_role=h11.CLIENT)
            remote_r, remote_w = await asyncio.open_connection(host, port)

            raw = origin_conn.send(h11.Request(
                method=req_event.method,
                target=new_target,
                headers=origin_headers,
            ))
            remote_w.write(raw)
            if body:
                remote_w.write(origin_conn.send(h11.Data(data=bytes(body))))
            remote_w.write(origin_conn.send(h11.EndOfMessage()))
            await remote_w.drain()

            # ════════════════════════════════════════════════════════════════
            # Phase 5 — Read response from origin, forward to client
            # ════════════════════════════════════════════════════════════════
            while True:
                data = await remote_r.read(65536)
                if not data:
                    break

                origin_conn.receive_data(data)

                while True:
                    event = origin_conn.next_event()
                    if event is h11.NEED_DATA:
                        break

                    if isinstance(event, h11.Response):
                        fwd_headers = [
                            (n, v) for n, v in event.headers
                            if n.lower() not in (b"transfer-encoding", b"connection")
                        ]
                        writer.write(client_conn.send(h11.Response(
                            status_code=event.status_code,
                            headers=fwd_headers,
                            reason=event.reason,
                        )))
                        await writer.drain()

                    elif isinstance(event, h11.Data):
                        writer.write(client_conn.send(
                            h11.Data(data=event.data)))
                        await writer.drain()

                    elif isinstance(event, h11.EndOfMessage):
                        writer.write(client_conn.send(h11.EndOfMessage()))
                        await writer.drain()
                        break

                    elif isinstance(event, h11.ConnectionClosed):
                        break

                if isinstance(event, (h11.EndOfMessage, h11.ConnectionClosed)):
                    break

            remote_w.close()

            # ════════════════════════════════════════════════════════════════
            # Phase 6 — Keep-alive check & cycle reset
            # ════════════════════════════════════════════════════════════════
            if client_conn.our_state in (h11.MUST_CLOSE, h11.CLOSED):
                break

            client_conn.start_next_cycle()

    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass
    except Exception:
        pass
    finally:
        if not tunnel_mode:
            writer.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HTTP/HTTPS proxy with dynamic domain allowlisting via Unix socket.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "socket_path",
        help="Unix socket path to listen on",
    )
    parser.add_argument(
        "--db-dir",
        default=None,
        help="Directory containing profile JSON files "
             "(default: profiles/ next to this script)",
    )
    parser.add_argument(
        "--profile",
        action="append",
        default=[],
        dest="profiles",
        help="Profile name(s) to load (repeatable, maps to <db-dir>/<name>.json)",
    )
    parser.add_argument(
        "patterns",
        nargs="*",
        help="Whitelist regex patterns (positional, merged into immutable baseline)",
    )
    return parser.parse_args(argv[1:])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Global allowlists instance (imported by handle())
ALLOWLISTS = Allowlists()


async def main(argv: list[str]) -> None:
    args = parse_args(argv)
    socket_path = args.socket_path

    # ── Resolve profile directory ────────────────────────────────────────
    profile_dir: str | None = args.db_dir
    if profile_dir is None:
        # Default: profiles/ next to this script
        default_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles")
        if os.path.isdir(default_dir):
            profile_dir = default_dir
        # If the default doesn't exist, just disable profiles (no error)

    # ── Compile baseline from CLI positional patterns ────────────────────
    baseline = AllowList.compile(args.patterns)

    # ── Load initial profiles ────────────────────────────────────────────
    profile_names = args.profiles
    if profile_dir and profile_names:
        try:
            raw = _load_profile_patterns(profile_dir, profile_names)
            initial_active = AllowList.compile(raw)
        except ProfileError as e:
            print(f"[http-proxy] Warning: {e}, starting without profiles", file=sys.stderr)
            initial_active = AllowList.empty()
    else:
        initial_active = AllowList.empty()

    # ── Wire up allowlists ───────────────────────────────────────────────
    ALLOWLISTS.setup(baseline, initial_active)
    total = len(ALLOWLISTS._active)
    src = []
    if baseline:
        src.append(f"{len(baseline)} CLI")
    if initial_active:
        src.append(f"{len(initial_active)} from profiles")
    print(
        f"[http-proxy] loaded {total} patterns ({', '.join(src)})",
        file=sys.stderr,
    )

    # ── Start file watcher ───────────────────────────────────────────────
    if profile_dir and profile_names:
        asyncio.create_task(_watch_profiles(ALLOWLISTS, profile_dir, profile_names))

    # ── Serve ────────────────────────────────────────────────────────────
    if os.path.exists(socket_path):
        os.remove(socket_path)
    server = await asyncio.start_unix_server(handle, socket_path)
    print(
        f"[http-proxy] listening on {socket_path}",
        file=sys.stderr,
    )
    await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main(sys.argv), debug=False)
