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

# Capabilities that can enable container → host escape
DANGEROUS_CAPS = frozenset({
    "ALL", "SYS_ADMIN", "SYS_RAWIO", "SYS_PTRACE", "SYS_MODULE",
    "DAC_OVERRIDE", "DAC_READ_SEARCH", "SYS_BOOT", "SYS_TIME",
    "SYS_TTY_CONFIG", "SYS_RESOURCE", "IPC_OWNER", "AUDIT_CONTROL",
    "AUDIT_WRITE", "MAC_ADMIN", "MAC_OVERRIDE", "BLOCK_SUSPEND",
    "LEASE", "LINUX_IMMUTABLE", "SYS_PACCT", "SYS_NICE",
    "WAKE_ALARM", "SYS_CHROOT", "NET_ADMIN", "NET_RAW",
    "NET_BROADCAST",
})

BLOCKED_SECURITY_OPTS = frozenset({
    "seccomp=unconfined",
    "apparmor=unconfined",
    "label=disable",
})
BLOCKED_SECURITY_OPT_PREFIXES = (
    "label=user:", "label=role:", "label=type:", "label=level:",
    "systempaths=unconfined",
)

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
def get_status_code(header_bytes):
    """Return the integer status code from the response line, or 0 on failure."""
    line = header_bytes.split(b"\r\n")[0].decode(errors="replace")
    parts = line.split(" ")
    try:
        return int(parts[1])
    except (IndexError, ValueError):
        return 0


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
        if hc.get("CgroupnsMode") == "host":
            return "CgroupnsMode=host is not allowed"

        # Capabilities that can enable escape
        for cap in hc.get("CapAdd", []):
            if cap.upper() in DANGEROUS_CAPS:
                return f"capability '{cap}' is not allowed"

        # Block all host device passthrough
        if hc.get("Devices"):
            return "device passthrough is not allowed (remove --device)"

        # Security options that weaken isolation
        for opt in hc.get("SecurityOpt", []):
            opt_lower = opt.lower()
            if opt_lower in BLOCKED_SECURITY_OPTS:
                return f"security option '{opt}' is not allowed"
            if any(opt_lower.startswith(p) for p in BLOCKED_SECURITY_OPT_PREFIXES):
                return f"security option '{opt}' is not allowed"

        # User namespace mode — host mode disables user-ns remapping
        if hc.get("UsernsMode") == "host":
            return "UsernsMode=host is not allowed"

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
        ("netns",     "network mode",   BLOCKED_NETWORK_MODES),
        ("pidns",     "PidMode",        {"host"}),
        ("ipcns",     "IpcMode",        {"host"}),
        ("cgroupns",  "CgroupnsMode",   {"host"}),
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

    # Libpod: capability additions
    for cap in body.get("cap_add", []):
        if cap.upper() in DANGEROUS_CAPS:
            return f"capability '{cap}' is not allowed"

    # Libpod: block all host device passthrough
    if body.get("devices"):
        return "device passthrough is not allowed (remove --device)"

    # Libpod: security options
    for opt in body.get("security_opt", []):
        opt_lower = opt.lower()
        if opt_lower in BLOCKED_SECURITY_OPTS:
            return f"security option '{opt}' is not allowed"
        if any(opt_lower.startswith(p) for p in BLOCKED_SECURITY_OPT_PREFIXES):
            return f"security option '{opt}' is not allowed"

    # Libpod: user namespace
    raw_userns = body.get("userns")
    if isinstance(raw_userns, str):
        if raw_userns == "host":
            return "userns=host is not allowed"
    elif isinstance(raw_userns, dict):
        if raw_userns.get("mode") == "host":
            return "userns=host is not allowed"

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

    try:
        content_length = int(headers.get("content-length", "0"))
    except (ValueError, TypeError):
        content_length = 0
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

BLOCKED_ENDPOINTS = re.compile(
    r"/(build|commit|pods/create|containers/[^/]+/exec)"
)

def is_blocked_endpoint(header_bytes):
    """Return an error string if the endpoint is blocked outright, else None."""
    line = get_request_line(header_bytes)
    if "POST" in line and re.search(BLOCKED_ENDPOINTS, line):
        m = re.search(r"(build|commit|pods/create|exec)", line)
        what = m.group(1) if m else "operation"
        return f"{what} is not allowed by sandbox policy"
    return None

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
    All exceptions are caught to prevent the connection handler from crashing.
    """
    try:
        header_bytes, rest = recv_until_double_crlf(upstream)
        if header_bytes is None:
            return

        # Forward the response header
        try:
            client.sendall(header_bytes)
        except OSError:
            return  # client disconnected

        headers = parse_headers(header_bytes)

        # --- Safe Content-Length parsing ---
        try:
            content_length = int(headers.get("content-length", "0"))
        except (ValueError, TypeError):
            content_length = 0

        te = headers.get("transfer-encoding", "").lower()

        # --- No-body responses ---
        # RFC 7230 §3.3.3: responses to HEAD requests and responses with status
        # 1xx (Informational), 204 (No Content) or 304 (Not Modified) NEVER have
        # a body and are complete after the header block.  Podman returns 204
        # for POST /containers/{id}/start with no Content-Length header; without
        # this check we would block on upstream.recv() waiting for an EOF that
        # only arrives when podman's HTTP server eventually times out the idle
        # keep-alive connection (observed ~10s).
        status = get_status_code(header_bytes)
        if (100 <= status < 200) or status in (204, 304):
            return  # response fully forwarded (headers only)

        # --- Body forwarding ---
        if content_length > 0:
            remaining = content_length - len(rest)
            if rest:
                try:
                    client.sendall(rest)
                except OSError:
                    return
            while remaining > 0:
                try:
                    chunk = upstream.recv(min(65536, remaining))
                except OSError:
                    return
                if not chunk:
                    break
                try:
                    client.sendall(chunk)
                except OSError:
                    return
                remaining -= len(chunk)

        elif "chunked" in te:
            # Forward chunked body, reading until the terminating 0\r\n\r\n
            buf = rest
            terminator = b"0\r\n\r\n"
            if buf:
                cutoff = buf.find(terminator)
                if cutoff >= 0:
                    try:
                        client.sendall(buf[:cutoff + len(terminator)])
                    except OSError:
                        pass
                    return
                try:
                    client.sendall(buf)
                except OSError:
                    return
            while not buf.endswith(terminator):
                try:
                    chunk = upstream.recv(65536)
                except OSError:
                    return
                if not chunk:
                    break
                # Check if this chunk contains the terminator, send only up to it
                cutoff = chunk.find(terminator)
                if cutoff >= 0:
                    client.sendall(chunk[:cutoff + len(terminator)])
                    return
                try:
                    client.sendall(chunk)
                except OSError:
                    return
                buf += chunk

        elif content_length == 0:
            # Explicit empty body (Content-Length: 0).  Nothing more to read;
            # the response is complete.  (Note: 204/304 with no Content-Length
            # is already handled above.)
            if rest:
                try:
                    client.sendall(rest)
                except OSError:
                    return

        else:
            # No Content-Length and no chunked encoding — only way to detect the
            # end of the body is upstream closing the connection (Connection:
            # close).  Read until EOF.
            if rest:
                try:
                    client.sendall(rest)
                except OSError:
                    return
            try:
                while True:
                    chunk = upstream.recv(65536)
                    if not chunk:
                        break
                    client.sendall(chunk)
            except OSError:
                pass
    except Exception:
        log("unexpected error forwarding response")

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

            # --- Container create policy enforcement ---
            if is_container_create(header_bytes):
                err = check_body(body_bytes)
                if err:
                    log(f"BLOCKED: {err}")
                    try:
                        client.sendall(forbidden(err))
                    except OSError:
                        pass
                    break

            # --- Endpoint blocking (exec, build, commit, pods) ---
            err = is_blocked_endpoint(header_bytes)
            if err:
                log(f"BLOCKED endpoint: {err}")
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
    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()

if __name__ == "__main__":
    main()
