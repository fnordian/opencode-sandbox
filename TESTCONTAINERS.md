# Running Java Testcontainers through the podman proxy

The podman proxy enforces a strict sandbox policy. Two rules affect
Testcontainers, and neither requires weakening the proxy:

1. `POST /containers/{id}/exec` is **conditionally allowed** — the proxy
   injects a marker label (`io.sandbox.proxy.created`) into every container
   created through it, and allows exec only for containers carrying that
   label. Containers created via ``podman run`` inside the sandbox get the
   label automatically; exec into them works without any configuration.
2. Bind-mount sources must be inside `PROJECT_DIR`.

A third concern — container networking — is now handled **automatically** by
the proxy (see §3): containers are placed in the sandbox's network namespace,
so their ports are reachable from inside the sandbox with no user
configuration.

With the configuration below, Testcontainers runs through the proxy with
**no proxy code changes and no extra permissions granted.**

## 1. Disable Ryuk (required)

Testcontainers starts a "Ryuk" container for resource cleanup. Ryuk
bind-mounts the host podman socket, which the proxy correctly rejects
because that path is outside `PROJECT_DIR`. Disable Ryuk via environment
variables on the Testcontainers client side:

```
TESTCONTAINERS_RYUK_DISABLED=true
TESTCONTAINERS_REUSE_CONTAINER=false
```

`TESTCONTAINERS_REUSE_CONTAINER=false` is required because reusable
containers depend on Ryuk bookkeeping.

Trade-off: if a test crashes, orphaned containers linger until you remove
them manually (`podman rm -f <id>`). The proxy does not change this.

## 2. Exec-based wait strategies now work

The proxy previously blocked exec outright. It now injects a marker label
(``io.sandbox.proxy.created``) into every container-create body that passes
through it at create time, and allows ``POST /containers/{id}/exec`` only for
containers that carry that label. The label is verified via an inspect
round-trip before the exec request is forwarded; the check is fail-closed
(any inspect error → exec denied).

**Consequence for Testcontainers:** the default ``Wait.forListeningPort()``
(``HostPortWaitStrategy``) **now works** for containers started via the
proxy.  ``execInContainer(...)`` in test code also works — all exec API calls
are forwarded for proxy-created containers.

If you exec into a container that was **not** created through the proxy
(e.g. a pre-existing container started directly against the real podman
socket from the host), the proxy returns 403. This is by design — only the
proxy socket is reachable from the sandbox, so a sandboxed process cannot
exec into a host-side container.

### Non-exec wait strategies (still recommended for some cases)

Exec-based readiness probes add latency and container dependency. These
strategies avoid exec entirely:

| Strategy | How it checks readiness | Exec API? | Use? |
|---|---|---|---|
| `Wait.forLogMessage(regex, n)` | Streams `GET /containers/{id}/logs` | No | **Yes** |
| `Wait.forHealthcheck()` | Reads `Health` from `GET /containers/{id}/json` (inspect) | No | **Yes** (only if the image ships a `HEALTHCHECK`) |
| `Wait.forHttp(path)` / `forHttps(path)` | Host-side HTTP probe on the mapped port | No | **Yes** |
| `Wait.forListeningPort()` (default) | Shell loop via `POST /containers/{id}/exec` | **Yes** | **Yes** (now works) |
| `Wait.forSuccessfulCommand(cmd)` | `ShellStrategy` → exec | **Yes** | **Yes** (now works) |

Note on ``forHealthcheck()``: very few official images ship a ``HEALTHCHECK``
(notably **not** ``postgres``, ``mysql``, ``redis``, ``nginx`` by default). Use it
only when you have added a ``HEALTHCHECK`` to the image yourself, or are using
an image that documents one. Otherwise ``forLogMessage`` or the default
``forListeningPort`` (now supported) are the simplest options.

## 3. Worked examples

### Redis

```java
GenericContainer<?> redis = new GenericContainer<>("redis:5.0.3-alpine")
    .withExposedPorts(6379)
    .waitingFor(Wait.forLogMessage(".*Ready to accept connections.*", 1));

redis.start();
```

### Postgres

The official `postgres` image logs the readiness line **twice** during
startup (once for the checkpointer, once for the main server). Match it
twice so the wait does not return early:

```java
PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
    .waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*", 2));

postgres.start();
```

### HTTP service

```java
GenericContainer<?> api = new GenericContainer<>("myapi:latest")
    .withExposedPorts(8080)
    .waitingFor(Wait.forHttp("/health").forStatusCode(200));

api.start();
```

## 4. Things that will not work through the proxy

- **Exec into containers NOT created through the proxy.** The proxy allows
  exec only for containers carrying the ``io.sandbox.proxy.created`` marker
  label (see §2). Containers started directly against the real podman socket
  from the host never receive this label. ``execInContainer(...)`` into such
  containers returns 403.
- **Ryuk / reusable containers.** Disabled per §1.
- **Images requiring ``--privileged``, ``--cap-add=<dangerous>``, ``--device``,
  ``seccomp=unconfined``, or ``--userns=host``.** Blocked by the create-time
  policy in ``check_body``, independent of the exec rule.

## 5. Container networking (handled automatically)

The sandbox runs with `--unshare-net`, so its `127.0.0.1` is a separate
loopback from the host's. Without intervention, a container created via host
podman attaches to the **host's** network namespace, and its published ports
are unreachable from inside the sandbox (you'd see `Connection refused` on
`127.0.0.1:<port>` even though `podman ps` shows a mapping).

The proxy fixes this transparently: for every `POST .../containers/create`,
it rewrites the request body to place the container in the **sandbox's**
network namespace (`netns.nsmode=path` / `HostConfig.NetworkMode=ns:<path>`).
The sandbox netns is discovered from the connecting client via `SO_PEERCRED`
on the proxy's Unix socket — no flag, no configuration.

Consequences:

- The container's listening ports appear **directly on the sandbox loopback**.
  `podman run -d -p 6379:6379 redis` followed by `nc 127.0.0.1 6379` from
  inside the sandbox just works. The `-p`/`--publish` flag is effectively a
  no-op in this mode (there is no host-side publishing); the exposed port is
  reachable at the same number on `127.0.0.1`.
- `--network=host` and `--network=bridge` are overridden to the sandbox netns;
  a container cannot escape to another host network namespace.
- **Testcontainers port mappings:** the proxy rewrites inspect responses so
  that `getMappedPort(exposedPort)` returns `exposedPort` itself — i.e. the
  exposed port is reported as a mapped port on `127.0.0.1`. This means
  Testcontainers' standard connection pattern works unchanged:

  ```java
  GenericContainer<?> redis = new GenericContainer<>("redis:5.0.3-alpine")
      .withExposedPorts(6379)
      .waitingFor(Wait.forLogMessage(".*Ready to accept connections.*", 1));

  redis.start();
  // getMappedPort(6379) returns 6379; connect on the sandbox loopback.
  RedisClient client = RedisClient.create(
      "redis://127.0.0.1:" + redis.getMappedPort(6379));
  ```

   The default ``Wait.forListeningPort()`` and any other exec-based wait
   strategy now work (see §2); the previous restriction (exec blocked
   outright) has been lifted.

  Note: because every container shares the same sandbox loopback, parallel
  tests that expose the same port number will conflict. Use distinct exposed
  ports per container, or run sequential test classes.

## 6. What still works

- ``copyFileFromContainer(...)`` — uses ``GET /containers/{id}/archive``, not exec.
- ``execInContainer(...)`` — uses ``POST /containers/{id}/exec``, which is now
  allowed for proxy-created containers (see §2).
- ``withLogConsumer(...)`` — uses the ``/logs`` stream.
- ``getMappedPort(...)`` — the proxy synthesizes port bindings in inspect
  responses so this returns the exposed port (see §5).
- Image pulls, create, start, stop, remove, inspect — all forwarded.
- Container ports on the sandbox loopback (see §5).

## 7. How exec authorization works

The proxy intercepts ``POST /containers/{id}/exec`` and, before forwarding,
opens a transient connection to the upstream podman socket to inspect the
target container (``GET /containers/{id}/json``). If the inspect response
contains ``Config.Labels["io.sandbox.proxy.created"] == "true"`` (or the
top-level ``Labels`` equivalent for libpod responses), the exec request is
forwarded. Otherwise a 403 is returned to the client.

**Why this is safe:** the proxy is the only podman socket reachable from
the sandbox (the real socket is not mounted by ``sandbox-wrapper-pp``).
The marker label is injected by the proxy into every create body at
create time, for both Docker-compat (``Labels``) and libpod (``labels``)
API shapes. A sandboxed process has no path to the real podman socket, so
it cannot create a container that bypasses the label injection, nor can it
add the label to a host-side container retroactively.

**Fail-closed:** if the inspect round-trip fails (upstream down, container
not found, parse error), exec is denied with a 403.

**One inspect round-trip per exec.** The overhead is negligible — exec is
not a hot path, and the inspect response is a small JSON document.
