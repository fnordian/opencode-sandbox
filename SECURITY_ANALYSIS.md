# Sandbox Wrapper (sandbox-wrapper-pp) — Security Analysis

## Architecture

The sandbox is a 3-component system:

| Component | File | Role |
|-----------|------|------|
| **Podman Proxy** | `podman-proxy.py` | Intercepts Podman API; enforces container creation policy |
| **HTTP Proxy** | `http-proxy.py` | HTTP(S) forward proxy with domain whitelist |
| **Sandbox Wrapper** | `sandbox-wrapper-pp` | Bubblewrap launcher + socat bridge orchestrator |

**Flow:** bwrap → isolated namespace → socat bridges loopback TCP to HTTP proxy Unix socket → target process runs with `http_proxy=http://127.0.0.1:8888`.

---

## 1. Sandbox (bwrap) Escapes

### 1a. FULL `/dev` — Critical
`--dev /dev` exposes all device nodes: `/dev/sd*` (raw disks), `/dev/dri/*` (GPU), `/dev/kvm` (virtualization), `/dev/net/tun` (net tunnels), `/dev/input/*` (input devices). Interactive with hardware directly.

### 1b. Wayland Display Socket — Critical
`$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY` is bind-mounted read-only. Allows screen capture, keylogging, and window creation on the user's desktop.

### 1c. D-Bus Session Bus — High
`/run/user/$UID/bus` mounted read-only. Permits observing session D-Bus traffic and calling methods on services without sender verification.

### 1d. `~/.config` Entirely Readable — High
SSH keys, cloud credentials, API tokens, browser cookies (if stored in `~/.config`).

### 1e. No IPC Namespace — Medium
`--unshare-ipc` is not used. Host shared memory (`shmget`/`shmat`), semaphores, and message queues are accessible.

### 1f. No User Namespace — Medium
Runs as the same UID/GID as the host user. File permissions are identical to the host.

### 1g. No Seccomp / Capabilities / cgroups — High
All syscalls available. No capabilities dropped. No CPU/memory/PID limits (fork-bomb vector).

---

## 2. Podman Proxy Bypasses

### 2a. Endpoint Filtering — Medium (label-gated exec)
`POST /containers/create` is inspected for policy violations. The following
endpoints are blocked outright by `BLOCKED_ENDPOINTS`:
- `POST /build` — blocked
- `POST /commit` — blocked
- `POST /pods/create` — blocked

`POST /containers/{id}/exec` is **conditionally allowed**: the proxy injects a
marker label (`io.sandbox.proxy.created`) into every container-create body that
passes through it, then verifies that label via an inspect round-trip before
forwarding an exec request. Only containers carrying this marker can be
exec'd into. The marker is injected for both Docker-compat (top-level
`Labels`) and Libpod (top-level `labels`) API shapes.

**Why this is safe:** the proxy is the only podman socket reachable from the
sandbox (the real socket is not mounted by `sandbox-wrapper-pp`). A sandboxed
process cannot create a container without going through the proxy, so every
sandbox-created container gets the label. A host-side container created
directly against the real podman socket never receives the label, and a
sandboxed process cannot forge the label on a host container because it has
no path to the real socket to create or modify a container without the
proxy's rewrite. The inspect round-trip is fail-closed (any error → exec
denied).

Prior behaviour: exec was blocked outright. See `TESTCONTAINERS.md` for the
testcontainers-client impact of the change.

### 2b. Capability Additions — Resolved
`check_body` blocks `--cap-add=ALL` and any capability in `DANGEROUS_CAPS`
(`SYS_ADMIN`, `NET_ADMIN`, `NET_RAW`, etc.) for both Docker-compat
(`HostConfig.CapAdd`) and Libpod (`cap_add`) formats, including the scalar
shorthand form (`"ALL"`).

### 2c. Device Passthrough — Resolved
`check_body` blocks any non-empty `HostConfig.Devices` / libpod `devices`.

### 2d. Security Options — Resolved
`check_body` blocks `seccomp=unconfined`, `apparmor=unconfined`, and
prefix-matched variants (`seccomp=*`, `apparmor=*`, `label=*`,
`no-new-privileges`) in both `HostConfig.SecurityOpt` and libpod
`security_opt`.

### 2e. User Namespace Mode — Resolved
`check_body` blocks `HostConfig.UsernsMode=host` and libpod `userns`
`{"mode":"host"}` / `"host"`.

### 2f. Named Volume Bypass — Low
Named volumes (not bind mounts from host paths) are not source-checked, but this is not a direct host escape.

### 2g. Binds Parsing Edge Case — Low
`bind.split(":")[0]` could fail with advanced Docker volume syntax (e.g., `src:dst:ro,z`). Source path is still correctly the first element.

### 2h. Network Namespace Forcing — New (informational)
The proxy now rewrites every container-create body to place the container in
the **sandbox's** network namespace (see §4). This is a behavior change with
security implications analyzed in §4 below.

---

## 3. Network Proxy Bypasses

### 3a. `127.0.0.1` Is Whitelisted — Low (in context)
Entire loopback interface is allowed. No practical impact since `--unshare-net` isolates the sandbox. Note: containers now share the sandbox netns (§4), so a containerized service listening on `127.0.0.1` is reachable from the sandbox via the HTTP proxy's `CONNECT 127.0.0.1:<port>` tunnel — but this is intended behavior, not a bypass (the service is in the sandbox's own netns).

### 3b. CONNECT Tunnels
Whitelisted domains can be tunnelled on any port, usable as a relay hop.

### 3c. Non-HTTP-Speaking Programs
Programs not honoring `http_proxy` fail (no direct net). Usability issue, not a bypass.

---

## 4. Container Network-Namespace Forcing

The proxy rewrites every `POST .../containers/create` body to attach the
container to the **sandbox's** network namespace (discovered via
`SO_PEERCRED` on the proxy's Unix socket → `/proc/<peer_pid>/ns/net`).
Without this, host podman would place containers on the host netns and
their ports would be unreachable from the sandbox's `--unshare-net`
loopback. The rewrite overrides both `--network=host` and
`--network=bridge` to `ns:<sandbox_netns>`.

### 4a. Netns Forging by a Sandboxed Process — Low
The netns path is derived from the **connecting client's PID** via
`SO_PEERCRED`. `SO_PEERCRED` is kernel-trusted and cannot be spoofed, so a
sandboxed process cannot make the proxy point at an arbitrary netns. The
path is always `/proc/<its_own_host_pid>/ns/net`, i.e. the sandbox's netns.
A sandboxed process has no way to make `getpeercred` return a different
PID.

### 4b. Containers Share the Sandbox Loopback — Intended
Containers now share the sandbox's `127.0.0.1`. This is the desired
behavior (services reachable from tests), but means a compromised
container can probe/connect to other services the sandbox exposes on
loopback (e.g. the socat HTTP-proxy bridge on `127.0.0.1:8888`, or other
containers started in the same sandbox). This is no worse than the
existing posture: the sandbox's own processes can already do this. A
container is not granted any additional host access by sharing the
sandbox netns — it has the same loopback-only view.

### 4c. Loss of Host Port Publishing — Usability (mostly mitigated)
In `ns:` mode, `-p`/`--publish` becomes a no-op (podman records the
binding as `null`). Containers cannot expose ports to the **host** via the
proxy. This is a usability constraint, not a security regression — the
previous behavior (ports on the host netns) was the bug being fixed. The
existing `--expose` flag in `sandbox-wrapper-pp` remains the supported way
to reach a sandbox-internal service from the host.

For client compatibility (Testcontainers' `getMappedPort()` model), the
proxy rewrites inspect responses to synthesize `127.0.0.1:<exposed>`
bindings for null entries. This is a presentation-layer convenience only —
no real host-side listener is created, and no new network exposure
results. The container is reachable at `127.0.0.1:<exposed>` because it
shares the sandbox netns, which is true regardless of the synthesized
binding.

### 4d. No Network Isolation Between Containers — Low
All containers started through the proxy share the **same** sandbox netns,
so they can communicate with each other on `127.0.0.1`. Previously
(containers on the host bridge) they were also reachable from the host and
each other. The new posture is strictly narrower: containers can reach
each other and the sandbox, but **not** the host network. This is a net
improvement in isolation, not a regression.

### 4e. `--network` Override Cannot Be Bypassed — Informational
The rewrite happens server-side in the proxy before the body reaches
podman. A sandboxed client cannot skip it: the create body always carries
the sandbox netns by the time podman sees it. `check_body`'s
`NetworkMode=host` / `netns=host` block still runs **after** the rewrite,
so even if a client requests host mode, the rewrite replaces it first and
no spurious block is triggered (the rewritten value is `ns:<path>`, which
is not in `BLOCKED_NETWORK_MODES`).

### 4f. Stale Netns Reference After Sandbox Exit — Low
The netns path `/proc/<pid>/ns/net` is valid only while the sandbox's bwrap
process (the PID returned by `SO_PEERCRED`) is alive. The proxy is
launched and killed by `sandbox-wrapper-pp` per sandbox session
(`trap cleanup EXIT`), so a stale reference cannot persist beyond the
session. If the proxy were ever run standalone outside the wrapper, a
dangling netns path would cause podman creates to fail (not a security
issue — a denial-of-service at most, and only for the proxy's own
session).

---

## Attack Vector Priority Matrix

| # | Vector | File | Difficulty | Impact | Status |
|---|--------|------|-----------|--------|--------|
| 1 | `podman build` with privileged Dockerfile | `podman-proxy.py` | Low | **Host compromise** | Blocked (`BLOCKED_ENDPOINTS`) |
| 2 | `podman exec` with `--privileged` | `podman-proxy.py` | Low | **Host compromise** | Conditional (label check) |
| 3 | `--cap-add=ALL` at container creation | `podman-proxy.py` | Low | **Host compromise** | Blocked (`check_body`) |
| 4 | `--device=/dev/sda` passthrough | `podman-proxy.py` | Low | **Host compromise** | Blocked (`check_body`) |
| 5 | `--security-opt seccomp=unconfined` | `podman-proxy.py` | Low | **Container escape** | Blocked (`check_body`) |
| 6 | `--userns=host` | `podman-proxy.py` | Low | **Reduced isolation** | Blocked (`check_body`) |
| 7 | Read `~/.config` secrets | `sandbox-wrapper-pp` | Trivial | **Credential theft** | Open (§1d) |
| 8 | Wayland screen capture | `sandbox-wrapper-pp` | Low | **Desktop compromise** | Open (§1b) |
| 9 | D-Bus keyring access | `sandbox-wrapper-pp` | Low | **Credential theft** | Open (§1c) |
| 10 | Raw `/dev/sd*` access (perms depend) | `sandbox-wrapper-pp` | Medium | **Filesystem bypass** | Open (§1a) |
| 11 | Shared IPC namespace | `sandbox-wrapper-pp` | Medium | **Data leak** | Open (§1e) |
| 12 | `podman commit` to create malicious image | `podman-proxy.py` | Low | **Supply-chain risk** | Blocked (`BLOCKED_ENDPOINTS`) |
| 13 | Container reaches host network | `podman-proxy.py` | — | **Network escape** | Mitigated by netns forcing (§4) |
| 14 | Container-to-container on sandbox loopback | `podman-proxy.py` | Low | **Lateral movement** | Accepted (§4d; no worse than sandbox processes) |
