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
import sys, os, socket, threading, json, re, argparse, struct

# Defaults for import/testing; overridden by argparse when run directly.
PROJECT_DIR = "/tmp"
LISTEN_SOCK = "/tmp/podman-proxy.sock"
UPSTREAM_SOCK = "/tmp/podman.sock"
VERBOSE = False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Podman socket proxy — enforces sandbox policies on container creation."
    )
    parser.add_argument("project_dir",
                        help="Project directory; bind mounts must stay inside this path.")
    parser.add_argument("listen_socket",
                        help="Path to the proxy's Unix domain socket (created by proxy).")
    parser.add_argument("upstream_socket",
                        help="Path to the real podman Unix domain socket (forward target).")
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

# Sandbox marker label — injected into every container create body so the proxy
# can verify, at exec time, that the target container was started from within the
# sandbox (only the proxy socket is reachable from the sandbox, so only
# proxy-processed creates carry this label).
SANDBOX_LABEL = "io.sandbox.proxy.created"

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

# ---- Sandbox network-namespace detection ------------------------------------
#
# The sandbox runs with --unshare-net, so its 127.0.0.1 is distinct from the
# host's. Containers created via host podman land on the host netns by default,
# making their ports unreachable from inside the sandbox. To fix this *without*
# burdening the user, the proxy rewrites every container-create body to place
# the container in the **sandbox's** network namespace, so the container's
# listening ports appear directly on the sandbox loopback.
#
# The sandbox's netns is discovered via SO_PEERCRED: the connecting podman
# client runs inside the sandbox, and the proxy (a host-side process) reads the
# peer's PID as seen from the host namespace. /proc/<host_pid>/ns/net is then
# the sandbox's netns file, which host podman accepts via `ns:`/`nsmode:path`.

_CONTENT_LENGTH_RE = re.compile(rb'content-length:\s*\d+', re.IGNORECASE)

def get_peer_netns_path(sock):
    """Return /proc/<peer_pid>/ns/net for the Unix-socket peer, or None.

    Uses SO_PEERCRED (Linux) to obtain the connecting process's PID as visible
    from this (host-side) process, then resolves its network-namespace file.
    Returns None if credentials are unavailable or the path does not exist.
    """
    try:
        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        pid = struct.unpack('iII', creds)[0]
        if pid <= 0:
            return None
        path = f"/proc/{pid}/ns/net"
        if os.path.exists(path):
            return path
    except OSError:
        pass
    return None

def force_netns(body_bytes, netns_path):
    """Rewrite a container-create body to join the given network namespace.

    Handles both API shapes podman exposes:
      * Libpod (flat): sets `netns` = {"nsmode":"path","value":<path>} and
        clears `portmappings` (publishing is meaningless in ns/path mode and
        podman itself nulls them when --network=ns: is used).
      * Docker-compatible (HostConfig): sets `NetworkMode` = "ns:<path>" and
        leaves PortBindings untouched (podman accepts and records them as
        null bindings, preserving the user's intent).

    Returns the (possibly replaced) body bytes. Non-JSON bodies are returned
    unchanged so the proxy never breaks a non-JSON request.
    """
    try:
        body = json.loads(body_bytes)
    except Exception:
        return body_bytes
    if not isinstance(body, dict):
        return body_bytes

    hc = body.get("HostConfig")
    if isinstance(hc, dict):
        # Docker-compatible format
        hc["NetworkMode"] = f"ns:{netns_path}"
        # Podman accepts PortBindings with ns mode (records them as null); keep
        # them so clients that inspect bindings still see the exposed ports.
    else:
        # Libpod format
        body["netns"] = {"nsmode": "path", "value": netns_path}
        body["portmappings"] = None
        body["Networks"] = None

    return json.dumps(body).encode()

def inject_sandbox_label(body_bytes):
    """Inject the sandbox marker label into a container-create body.

    Handles both Docker-compat (top-level ``Labels``) and Libpod (top-level
    ``labels``).  Merges with any existing labels so the caller's labels are
    preserved.  Non-JSON bodies are returned unchanged.
    """
    try:
        body = json.loads(body_bytes)
    except Exception:
        return body_bytes
    if not isinstance(body, dict):
        return body_bytes

    # Docker-compat body shape — top-level "Labels"
    labels = body.get("Labels")
    if not isinstance(labels, dict):
        labels = {}
    if SANDBOX_LABEL not in labels:
        labels[SANDBOX_LABEL] = "true"
        body["Labels"] = labels

    # Libpod body shape — top-level "labels" (lowercase)
    llabels = body.get("labels")
    if not isinstance(llabels, dict):
        llabels = {}
    if SANDBOX_LABEL not in llabels:
        llabels[SANDBOX_LABEL] = "true"
        body["labels"] = llabels

    return json.dumps(body).encode()

def rewrite_content_length(header_bytes, new_length):
    """Return header_bytes with the Content-Length value replaced.

    `header_bytes` is the full request header block including the trailing
    CRLFCRLF. If a Content-Length header exists it is rewritten in place
    (case-insensitively); otherwise one is inserted before the terminator.
    """
    replacement = b'Content-Length: ' + str(new_length).encode()
    if _CONTENT_LENGTH_RE.search(header_bytes):
        return _CONTENT_LENGTH_RE.sub(replacement, header_bytes, count=1)
    # No Content-Length header: strip the trailing CRLFCRLF, add a CRLF for the
    # new header line, then the header, then the terminating CRLFCRLF.
    return header_bytes[:-4] + b'\r\n' + replacement + b'\r\n\r\n'


# ---- Policy check -----------------------------------------------------------

def check_body(body_bytes):
    """Return an error string if the request body violates policy, else None."""
    try:
        body = json.loads(body_bytes)
    except Exception:
        return None  # not JSON, let podman handle it

    # ============ Docker-compatible API format (HostConfig) ============
    hc = body.get("HostConfig") or {}
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
        cap_add = hc.get("CapAdd") or []
        if isinstance(cap_add, str):
            # Podman/Docker accept a scalar shorthand like "ALL"
            if cap_add.upper() == "ALL":
                return "capability 'ALL' is not allowed"
            cap_add = [cap_add]
        for cap in cap_add:
            if cap.upper() in DANGEROUS_CAPS:
                return f"capability '{cap}' is not allowed"

        # Block all host device passthrough
        if hc.get("Devices"):
            return "device passthrough is not allowed (remove --device)"

        # Security options that weaken isolation
        sec_opts = hc.get("SecurityOpt") or []
        if isinstance(sec_opts, str):
            sec_opts = [sec_opts]
        for opt in sec_opts:
            opt_lower = opt.lower()
            if opt_lower in BLOCKED_SECURITY_OPTS:
                return f"security option '{opt}' is not allowed"
            if any(opt_lower.startswith(p) for p in BLOCKED_SECURITY_OPT_PREFIXES):
                return f"security option '{opt}' is not allowed"

        # User namespace mode — host mode disables user-ns remapping
        if hc.get("UsernsMode") == "host":
            return "UsernsMode=host is not allowed"

        binds = hc.get("Binds") or []
        if isinstance(binds, str):
            binds = [binds]
        for bind in binds:
            host_part = bind.split(":")[0]
            real = os.path.realpath(host_part)
            if not (real == PROJECT_DIR or real.startswith(PROJECT_DIR + "/")):
                return f"bind mount '{host_part}' is outside project directory"

        for mount in (hc.get("Mounts") or []):
            if mount.get("Type") == "bind" or mount.get("type") == "bind":
                src = mount.get("Source", "") or mount.get("source", "")
                if src:
                    real = os.path.realpath(src)
                    if not (real == PROJECT_DIR or real.startswith(PROJECT_DIR + "/")):
                        return f"bind mount source '{src}' is outside project directory"

        for mount in (body.get("Mounts") or []):
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
    cap_add = body.get("cap_add") or []
    if isinstance(cap_add, str):
        if cap_add.upper() == "ALL":
            return "capability 'ALL' is not allowed"
        cap_add = [cap_add]
    for cap in cap_add:
        if cap.upper() in DANGEROUS_CAPS:
            return f"capability '{cap}' is not allowed"

    # Libpod: block all host device passthrough
    if body.get("devices"):
        return "device passthrough is not allowed (remove --device)"

    # Libpod: security options
    sec_opts = body.get("security_opt") or []
    if isinstance(sec_opts, str):
        sec_opts = [sec_opts]
    for opt in sec_opts:
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
    for mount in (body.get("mounts") or []):
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

def is_container_inspect(header_bytes):
    """Match GET /containers/{id}/json (Docker-compat and libpod, versioned or not)."""
    line = get_request_line(header_bytes)
    if not line.startswith("GET "):
        return False
    return re.search(r"/containers/[^/]+/json", line) is not None

def rewrite_inspect_ports(body_bytes):
    """Synthesize port bindings for an inspect response so clients using the
    Docker port-mapping model (e.g. Testcontainers getMappedPort) see each
    exposed port as its own mapped port on 127.0.0.1.

    In ns: mode podman records exposed ports with `null` bindings (no
    host-side publishing). The container is nonetheless reachable at
    127.0.0.1:<exposed> on the sandbox loopback, so returning that as the
    "mapped port" is functionally accurate. Returns (new_body, changed).
    """
    try:
        body = json.loads(body_bytes)
    except Exception:
        return body_bytes, False
    if not isinstance(body, dict):
        return body_bytes, False
    ns = body.get("NetworkSettings")
    if not isinstance(ns, dict):
        return body_bytes, False
    ports = ns.get("Ports")
    if not isinstance(ports, dict):
        return body_bytes, False
    changed = False
    for key, binding in list(ports.items()):
        if binding is None or (isinstance(binding, list) and len(binding) == 0):
            # key is like "6379/tcp" — the exposed port is the host port too
            port_num = key.split("/")[0]
            ports[key] = [{"HostIp": "127.0.0.1", "HostPort": port_num}]
            changed = True
    if not changed:
        return body_bytes, False
    return json.dumps(body).encode(), True

BLOCKED_ENDPOINTS = re.compile(
    r"/(build|commit|pods/create)"
)

def is_blocked_endpoint(header_bytes):
    """Return an error string if the endpoint is blocked outright, else None."""
    line = get_request_line(header_bytes)
    if "POST" in line and re.search(BLOCKED_ENDPOINTS, line):
        m = re.search(r"(build|commit|pods/create)", line)
        what = m.group(1) if m else "operation"
        return f"{what} is not allowed by sandbox policy"
    return None

# ---- Exec request helpers (label-based authorization) ------------------------

_EXEC_RE = re.compile(r"POST\s+.*/containers/([^/\s]+)/exec\b")

def is_exec_request(header_bytes):
    """Return True if the request is a POST to a container exec endpoint."""
    line = get_request_line(header_bytes)
    return bool(_EXEC_RE.search(line))

def extract_container_id(header_bytes):
    """Extract the container ID from an exec request URL, or None."""
    line = get_request_line(header_bytes)
    m = _EXEC_RE.search(line)
    return m.group(1) if m else None

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

def _dechunk_body(upstream, rest):
    """Read the remainder of a chunked transfer-encoded body from upstream,
    decode it, and return the de-chunked body bytes.  Returns None on failure.

    `rest` is the bytes already read after the header CRLFCRLF (may be empty).
    """
    buf = rest
    terminator = b"0\r\n\r\n"
    while terminator not in buf:
        try:
            chunk = upstream.recv(65536)
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk

    end = buf.index(terminator) + len(terminator)
    raw = buf[:end]

    body = b""
    pos = 0
    while pos < len(raw):
        crlf = raw.find(b'\r\n', pos)
        if crlf < 0:
            break
        hex_size = raw[pos:crlf]
        try:
            size = int(hex_size, 16)
        except ValueError:
            break
        if size == 0:
            break
        chunk_start = crlf + 2
        chunk_end = chunk_start + size
        body += raw[chunk_start:chunk_end]
        pos = chunk_end + 2  # trailing \r\n after chunk data
    return body


def _strip_transfer_encoding(header_bytes):
    """Return header_bytes with any Transfer-Encoding header removed.

    Does not modify other headers or the request/status line.
    """
    # Match the full line containing Transfer-Encoding (case-insensitive)
    te_re = re.compile(rb'^transfer-encoding:\s*.+\r\n', re.IGNORECASE | re.MULTILINE)
    return te_re.sub(b'', header_bytes)


def forward_inspect_response(upstream, client):
    """Forward a container-inspect response, rewriting null port bindings to
    synthetic 127.0.0.1:<exposed> mappings (see rewrite_inspect_ports).

    Buffers the full response body regardless of framing (chunked,
    Content-Length, or connection-close) so the rewrite can be applied,
    then always delivers the response with Content-Length framing.
    """
    try:
        header_bytes, rest = recv_until_double_crlf(upstream)
        if header_bytes is None:
            return

        headers = parse_headers(header_bytes)
        try:
            content_length = int(headers.get("content-length", "0"))
        except (ValueError, TypeError):
            content_length = 0
        te = headers.get("transfer-encoding", "").lower()

        status = get_status_code(header_bytes)
        if (100 <= status < 200) or status in (204, 304):
            try:
                client.sendall(header_bytes)
            except OSError:
                pass
            return

        # ---- Buffer the full response body ----
        if content_length > 0:
            body = rest
            while len(body) < content_length:
                try:
                    chunk = upstream.recv(min(65536, content_length - len(body)))
                except OSError:
                    return
                if not chunk:
                    break
                body += chunk
            body = body[:content_length]

        elif "chunked" in te:
            body = _dechunk_body(upstream, rest)
            if body is None:
                # Buffering failed — forward headers + rest verbatim
                try:
                    client.sendall(header_bytes + rest)
                except OSError:
                    pass
                return

        else:
            # Connection-close: read until EOF
            body = rest
            try:
                while True:
                    chunk = upstream.recv(65536)
                    if not chunk:
                        break
                    body += chunk
            except OSError:
                pass

        # ---- Attempt port-binding rewrite; always re-frame as Content-Length ----
        new_body, changed = rewrite_inspect_ports(body)
        # Strip any Transfer-Encoding header (we always send Content-Length now)
        new_header = _strip_transfer_encoding(header_bytes)
        new_header = rewrite_content_length(new_header, len(new_body if changed else body))

        try:
            client.sendall(new_header + (new_body if changed else body))
        except OSError:
            return

        if changed:
            log("rewrote inspect ports -> sandbox loopback")
    except Exception:
        log("unexpected error forwarding inspect response")

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


# ---- Exec label verification -------------------------------------------------

def container_has_sandbox_label(container_id):
    """Check whether *container_id* carries the sandbox marker label.

    Opens a transient connection to the upstream podman socket, sends an
    inspect request, and checks for *SANDBOX_LABEL* in both ``Config.Labels``
    (Docker-compat inspect shape) and top-level ``Labels`` (libpod fallback).

    Fail-closed: returns ``False`` on any connectivity, parse, or
    non-2xx response.
    """
    try:
        up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        up.settimeout(10)
        up.connect(UPSTREAM_SOCK)
        req = (
            f"GET /containers/{container_id}/json HTTP/1.1\r\n"
            f"Host: podman\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        up.sendall(req)

        header_bytes, rest = recv_until_double_crlf(up)
        if header_bytes is None:
            up.close()
            return False

        status = get_status_code(header_bytes)
        if status < 200 or status >= 300:
            up.close()
            return False

        # Read the full response body
        headers = parse_headers(header_bytes)
        try:
            content_length = int(headers.get("content-length", "0"))
        except (ValueError, TypeError):
            content_length = 0
        te = headers.get("transfer-encoding", "").lower()

        if content_length > 0:
            body = rest
            while len(body) < content_length:
                try:
                    chunk = up.recv(min(65536, content_length - len(body)))
                except OSError:
                    break
                if not chunk:
                    break
                body += chunk
            body = body[:content_length]
        elif "chunked" in te:
            body = _dechunk_body(up, rest)
            if body is None:
                up.close()
                return False
        else:
            # Connection-close: read until EOF
            body = rest
            try:
                while True:
                    chunk = up.recv(65536)
                    if not chunk:
                        break
                    body += chunk
            except OSError:
                pass

        up.close()

        try:
            info = json.loads(body)
        except Exception:
            return False

        # Docker-compat inspect shape
        config = info.get("Config") or {}
        clabels = config.get("Labels") or {}
        if SANDBOX_LABEL in clabels:
            return True

        # Libpod inspect shape (top-level Labels)
        tlabels = info.get("Labels") or {}
        if SANDBOX_LABEL in tlabels:
            return True

        return False

    except Exception:
        return False


def forward_exec_if_allowed(header_bytes, body_bytes, client):
    """Authorize an exec request via label check, then forward if allowed.

    Returns the upstream socket with the original exec request already sent
    on success, or ``None`` if the exec was denied (a 403 was sent to the
    client).
    """
    cid = extract_container_id(header_bytes)
    if not cid:
        log("exec request: could not extract container ID")
        try:
            client.sendall(forbidden("exec request malformed"))
        except OSError:
            pass
        return None

    log(f"exec request for container {cid} — checking sandbox label")

    if not container_has_sandbox_label(cid):
        log(f"exec DENIED — container {cid} lacks sandbox label")
        try:
            client.sendall(forbidden(
                "exec is only allowed on containers created "
                "through the sandbox proxy"
            ))
        except OSError:
            pass
        return None

    log(f"exec ALLOWED — container {cid} has sandbox label")

    # Open a fresh upstream connection and send the original exec request
    try:
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        upstream.settimeout(30)
        upstream.connect(UPSTREAM_SOCK)
        upstream.sendall(header_bytes + body_bytes)
        return upstream
    except OSError:
        log("exec: failed to connect/send to upstream")
        return None


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
                # Place the container in the sandbox's network namespace so its
                # ports are reachable on the sandbox loopback (the sandbox runs
                # --unshare-net; without this, host podman would attach the
                # container to the host netns and its ports would be invisible
                # from inside the sandbox). Discovered automatically from the
                # connecting client via SO_PEERCRED — no user flag needed.
                netns_path = get_peer_netns_path(client)
                if netns_path:
                    new_body = force_netns(body_bytes, netns_path)
                    if new_body != body_bytes:
                        body_bytes = new_body
                        header_bytes = rewrite_content_length(
                            header_bytes, len(body_bytes))
                        log(f"forced container netns -> {netns_path}")
                else:
                    log("warning: could not determine sandbox netns; "
                        "container will use podman's default network")

                # Inject sandbox marker label so exec is allowed for containers
                # created through the proxy.
                new_body = inject_sandbox_label(body_bytes)
                if new_body != body_bytes:
                    body_bytes = new_body
                    header_bytes = rewrite_content_length(
                        header_bytes, len(body_bytes))
                    log("injected sandbox marker label")

                err = check_body(body_bytes)
                if err:
                    log(f"BLOCKED: {err}")
                    try:
                        client.sendall(forbidden(err))
                    except OSError:
                        pass
                    break

            # --- Endpoint blocking (build, commit, pods) ---
            err = is_blocked_endpoint(header_bytes)
            if err:
                log(f"BLOCKED endpoint: {err}")
                try:
                    client.sendall(forbidden(err))
                except OSError:
                    pass
                break

            # --- Exec request: label-based authorization ---
            upstream = None
            if is_exec_request(header_bytes):
                upstream = forward_exec_if_allowed(
                    header_bytes, body_bytes, client)
                if upstream is None:
                    break   # denied or error; 403 already sent

            # --- Forward to upstream (only if not already connected) ---
            if upstream is None:
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
            # Inspect responses get port bindings synthesized so clients using
            # the Docker port-mapping model (Testcontainers getMappedPort) see
            # the exposed port as a mapped port on the sandbox loopback.
            if is_container_inspect(header_bytes):
                forward_inspect_response(upstream, client)
            else:
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
