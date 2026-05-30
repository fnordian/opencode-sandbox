#!/usr/bin/env python3
"""
Podman socket proxy that enforces sandbox policies on container creation.

Usage:
    podman-proxy [-h] <project_dir> <listen_socket> <upstream_socket>

Positional arguments:
    project_dir       Project directory; bind mounts must stay inside this path.
    listen_socket     Path to the proxy's Unix domain socket (created by proxy).
    upstream_socket   Path to the real podman Unix domain socket (forward target).

Options:
    -h, --help        Show this help message and exit.
"""
import sys, os, socket, threading, json, re, argparse

parser = argparse.ArgumentParser(
    description="Podman socket proxy — enforces sandbox policies on container creation."
)
parser.add_argument("project_dir", help="Project directory; bind mounts must stay inside this path.")
parser.add_argument("listen_socket", help="Path to the proxy's Unix domain socket (created by proxy).")
parser.add_argument("upstream_socket", help="Path to the real podman Unix domain socket (forward target).")
parser.add_argument("-v", "--verbose", action="store_true",
                    help="Print diagnostic messages to stderr.")

args = parser.parse_args()

PROJECT_DIR = os.path.realpath(args.project_dir)
LISTEN_SOCK = args.listen_socket
UPSTREAM_SOCK = args.upstream_socket
VERBOSE = args.verbose

BLOCKED_NETWORK_MODES = {"host"}

# ---- Helpers ----------------------------------------------------------------

def log(msg):
    """Log diagnostic message to stderr (only if --verbose is set)."""
    if VERBOSE:
        sys.stderr.write(f"[podman-proxy] {msg}\n")
        sys.stderr.flush()

def recv_until_double_crlf(sock):
    """Read from sock until \\r\\n\\r\\n is found.
    Return (header_bytes_with_sep, extra_bytes)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        try:
            chunk = sock.recv(4096)
        except OSError:
            return None, None
        if not chunk:
            return None, None
        buf += chunk
    h, rest = buf.split(b"\r\n\r\n", 1)
    return h + b"\r\n\r\n", rest

def parse_headers(header_bytes):
    """Parse HTTP headers into a dict (lowercase keys)."""
    text = header_bytes.decode(errors="replace")
    headers = {}
    for line in text.split("\r\n")[1:]:
        if ": " in line:
            k, v = line.split(": ", 1)
            headers[k.lower()] = v
    return headers

def get_request_line(header_bytes):
    return header_bytes.split(b"\r\n")[0].decode(errors="replace")

# ---- Policy check -----------------------------------------------------------

def check_body(body_bytes):
    """Return an error string if the request body violates policy, else None."""
    try:
        body = json.loads(body_bytes)
    except Exception:
        return None  # not JSON, let podman handle it

    # ============ Docker-compatible API format (HostConfig) ============
    hc = body.get("HostConfig", {})
    if hc:
        if hc.get("Privileged"):
            return "privileged mode is not allowed"

        nm = hc.get("NetworkMode", "")
        if nm in BLOCKED_NETWORK_MODES:
            return f"network mode '{nm}' is not allowed"

        if hc.get("PidMode") == "host":
            return "PidMode=host is not allowed"
        if hc.get("IpcMode") == "host":
            return "IpcMode=host is not allowed"

        for bind in hc.get("Binds", []):
            host_part = bind.split(":")[0]
            real = os.path.realpath(host_part)
            if not (real == PROJECT_DIR or real.startswith(PROJECT_DIR + "/")):
                return f"bind mount '{host_part}' is outside project directory"

        for mount in hc.get("Mounts", []):
            if mount.get("Type") == "bind" or mount.get("type") == "bind":
                src = mount.get("Source", "") or mount.get("source", "")
                if src:
                    real = os.path.realpath(src)
                    if not (real == PROJECT_DIR or real.startswith(PROJECT_DIR + "/")):
                        return f"bind mount source '{src}' is outside project directory"

        for mount in body.get("Mounts", []):
            if mount.get("Type") == "bind" or mount.get("type") == "bind":
                src = mount.get("Source", "") or mount.get("source", "")
                if src:
                    real = os.path.realpath(src)
                    if not (real == PROJECT_DIR or real.startswith(PROJECT_DIR + "/")):
                        return f"bind mount source '{src}' is outside project directory"

    # ============ Libpod API format (flat structure) ============
    if body.get("privileged"):
        return "privileged mode is not allowed"

    # Namespace modes (libpod: can be a string like "host" or an object {"mode":"host"})
    for ns_key, label, blocked in (
        ("netns",  "network mode",   BLOCKED_NETWORK_MODES),
        ("pidns",  "PidMode",        {"host"}),
        ("ipcns",  "IpcMode",        {"host"}),
    ):
        raw = body.get(ns_key)
        if isinstance(raw, str):
            mode = raw
        elif isinstance(raw, dict):
            mode = raw.get("mode", "") or raw.get("nsmode", "")
        else:
            continue
        if mode in blocked:
            return f"{label}='{mode}' is not allowed"

    # Libpod mounts (lowercase!)
    for mount in body.get("mounts", []):
        if isinstance(mount, dict):
            src = mount.get("source", "") or mount.get("Source", "")
            mtype = mount.get("type", "").lower()
            if not src:
                continue
            if mtype in ("bind",) or (mtype == "volume" and src.startswith("/")):
                real = os.path.realpath(src)
                if not (real == PROJECT_DIR or real.startswith(PROJECT_DIR + "/")):
                    return f"bind mount source '{src}' is outside project directory"

    return None

def forbidden(msg):
    body = json.dumps({"message": f"SANDBOX POLICY: {msg}"}).encode()
    return (
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: application/json\r\n"
        b"Connection: close\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )

# ---- HTTP request parsing ---------------------------------------------------

def read_http_request(sock):
    """Read one HTTP request from sock, return (headers_bytes, body_bytes) or None."""
    raw = b""
    while b"\r\n\r\n" not in raw:
        try:
            chunk = sock.recv(4096)
        except OSError:
            return None, None
        if not chunk:
            return None, None
        raw += chunk

    header_part, rest = raw.split(b"\r\n\r\n", 1)
    headers = parse_headers(header_part)

    content_length = int(headers.get("content-length", 0))
    body = rest
    while len(body) < content_length:
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        body += chunk

    return header_part + b"\r\n\r\n", body[:content_length]

def is_container_create(header_bytes):
    line = get_request_line(header_bytes)
    return "POST" in line and re.search(r"/containers/create", line) is not None

# ---- Streaming endpoints (infinite response) --------------------------------
INFINITE_STREAM_PATTERNS = re.compile(
    r"/(attach|logs|exec/[^/]+/start|events|stats|ws|upgrade)"
)

def is_infinite_stream(request_line):
    return bool(re.search(INFINITE_STREAM_PATTERNS, request_line))

# ---- Pipe sockets (blind bidirectional forwarding) --------------------------

def pipe_sockets(src, dst):
    try:
        while True:
            try:
                data = src.recv(65536)
            except socket.timeout:
                break  # idle timeout
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try: src.close()
        except: pass
        try: dst.close()
        except: pass

# ---- Forward finite response ------------------------------------------------

def forward_finite_response(upstream, client):
    """
    Forward a complete response from upstream to client.
    Handles Content-Length, chunked, and connection-close responses.
    """
    header_bytes, rest = recv_until_double_crlf(upstream)
    if header_bytes is None:
        return

    # Forward the response header
    client.sendall(header_bytes)

    headers = parse_headers(header_bytes)
    content_length = int(headers.get("content-length", 0))
    te = headers.get("transfer-encoding", "").lower()

    if content_length > 0:
        remaining = content_length - len(rest)
        if rest:
            client.sendall(rest)
        while remaining > 0:
            chunk = upstream.recv(min(65536, remaining))
            if not chunk:
                break
            client.sendall(chunk)
            remaining -= len(chunk)

    elif te in ("chunked", "chunked\r"):
        buf = rest
        if buf:
            client.sendall(buf)
        while not buf.endswith(b"0\r\n\r\n"):
            chunk = upstream.recv(65536)
            if not chunk:
                break
            client.sendall(chunk)
            buf += chunk

    elif content_length == 0:
        # Explicit empty body (e.g. 204 No Content) — nothing more to read
        if rest:
            client.sendall(rest)

    else:
        # Connection: close or unknown — read until EOF
        if rest:
            client.sendall(rest)
        try:
            while True:
                chunk = upstream.recv(65536)
                if not chunk:
                    break
                client.sendall(chunk)
        except Exception:
            pass

# ---- Main connection handler ------------------------------------------------

def handle(client):
    try:
        while True:
            # Idle timeout prevents hanging if client never sends another request
            client.settimeout(1.5)
            try:
                header_bytes, body_bytes = read_http_request(client)
            except OSError:
                break
            except socket.timeout:
                log("idle timeout — closing connection")
                break
            if header_bytes is None:
                break
            client.settimeout(None)

            rl = get_request_line(header_bytes)

            # --- Policy enforcement ---
            if is_container_create(header_bytes):
                err = check_body(body_bytes)
                if err:
                    log(f"BLOCKED: {err}")
                    try:
                        client.sendall(forbidden(err))
                    except OSError:
                        pass
                    break

            # --- Forward to upstream ---
            try:
                upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                upstream.settimeout(30)
                upstream.connect(UPSTREAM_SOCK)
                upstream.sendall(header_bytes + body_bytes)
            except OSError:
                break

            # --- Streaming (infinite response)? ---
            if is_infinite_stream(rl):
                resp_header, initial_rest = recv_until_double_crlf(upstream)
                if resp_header is None:
                    upstream.close()
                    break
                try:
                    client.sendall(resp_header + initial_rest)
                except OSError:
                    upstream.close()
                    break
                # Upstream→client: generous timeout for container output
                upstream.settimeout(30.0)
                # client→upstream: short timeout — if no stdin data flows,
                # the session is likely done
                client.settimeout(1.0)
                t = threading.Thread(
                    target=pipe_sockets, args=(upstream, client),
                    daemon=True
                )
                t.start()
                pipe_sockets(client, upstream)
                break

            # --- Finite response ---
            forward_finite_response(upstream, client)
            upstream.close()
    finally:
        try:
            client.close()
        except Exception:
            pass

# ---- Main ----------------------------------------------------------------

def main():
    if os.path.exists(LISTEN_SOCK):
        os.unlink(LISTEN_SOCK)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(LISTEN_SOCK)
    srv.listen(16)
    sys.stdout.write("ready\n")
    sys.stdout.flush()
    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()

if __name__ == "__main__":
    main()
