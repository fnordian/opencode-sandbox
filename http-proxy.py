#!/usr/bin/env python3
"""Lightweight HTTP/HTTPS proxy with domain whitelisting via Unix Socket."""
import asyncio, re, sys, os
from urllib.parse import urlparse

import h11

# Arg 1: Socket Path, Arg 2+: Whitelist Patterns
SOCKET_PATH = sys.argv[1]
WHITELIST = [re.compile(p, re.IGNORECASE) for p in sys.argv[2:]]

HOP_BY_HOP = frozenset({
    b"proxy-connection", b"connection", b"keep-alive",
    b"transfer-encoding", b"upgrade",
})

# ---- Helpers ----------------------------------------------------------------

def allowed(host):
    return any(p.match(host) for p in WHITELIST) if host else False


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


# ---- Handlers ---------------------------------------------------------------

async def handle(reader, writer):
    client_conn = h11.Connection(our_role=h11.SERVER)
    try:
        while True:
            # ================================================================
            # Phase 1 — Read one complete request from the proxy client
            # ================================================================
            req_event = None
            body = bytearray()
            eom_received = False

            while not eom_received:
                # First try to consume buffered events from h11 without
                # blocking on the network.  Only call reader.read() when
                # h11 explicitly signals NEED_DATA.
                event = client_conn.next_event()
                if event is h11.NEED_DATA:
                    data = await asyncio.wait_for(reader.read(65536), timeout=60.0)
                    if not data:
                        return  # client disconnected
                    client_conn.receive_data(data)
                    continue
                if event is h11.PAUSED:
                    # h11 completed one cycle and data for the next
                    # request arrived before we called start_next_cycle().
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

            # ================================================================
            # Phase 2 — CONNECT tunnel (same pipe-based approach as before)
            # ================================================================
            if req_event.method == b"CONNECT":
                raw_target = req_event.target.decode()
                if ":" in raw_target:
                    host, port_s = raw_target.rsplit(":", 1)
                    port = int(port_s)
                else:
                    host, port = raw_target, 443

                if not allowed(host):
                    writer.write(client_conn.send(
                        h11.Response(status_code=403, headers=[(b"connection", b"close")])))
                    writer.write(client_conn.send(h11.EndOfMessage()))
                    await writer.drain()
                    return

                writer.write(client_conn.send(
                    h11.Response(status_code=200, headers=[])))
                await writer.drain()

                remote_r, remote_w = await asyncio.open_connection(host, port)
                asyncio.create_task(pipe(reader, remote_w))
                asyncio.create_task(pipe(remote_r, writer))
                return  # tunnel owns both connections from here

            # ================================================================
            # Phase 3 — HTTP: parse host, check allowlist, rewrite URI
            # ================================================================
            host, port = _extract_host_port(req_event.headers)

            if not allowed(host):
                writer.write(client_conn.send(
                    h11.Response(status_code=403, headers=[(b"connection", b"close")])))
                writer.write(client_conn.send(h11.EndOfMessage()))
                await writer.drain()
                return

            new_target = _rewrite_target(req_event.target)

            # Filter out hop-by-hop headers before forwarding to origin
            origin_headers = [
                (n, v) for n, v in req_event.headers if n.lower() not in HOP_BY_HOP
            ]

            # ================================================================
            # Phase 4 — Forward request to origin
            # ================================================================
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

            # ================================================================
            # Phase 5 — Read response from origin, forward to client
            # ================================================================
            # Keep reading until we have a complete response (including body)
            # or the origin closes the connection.
            while True:
                data = await remote_r.read(65536)
                if not data:
                    break  # origin closed

                origin_conn.receive_data(data)

                while True:
                    event = origin_conn.next_event()
                    if event is h11.NEED_DATA:
                        break

                    if isinstance(event, h11.Response):
                        # Forward response to client via client_conn.
                        # Strip Transfer-Encoding from forwarded headers;
                        # h11 will add it automatically if needed.
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
                        break  # response body complete

                    elif isinstance(event, h11.ConnectionClosed):
                        break

                if isinstance(event, (h11.EndOfMessage, h11.ConnectionClosed)):
                    break

            remote_w.close()

            # ================================================================
            # Phase 6 — Keep-alive check & cycle reset
            # ================================================================
            if client_conn.our_state in (h11.MUST_CLOSE, h11.CLOSED):
                break

            # our_state == DONE → reset for next request-response cycle
            client_conn.start_next_cycle()

    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass  # client idle or dropped connection
    except Exception:
        pass
    finally:
        writer.close()


# ---- Main -------------------------------------------------------------------

async def main():
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)
    server = await asyncio.start_unix_server(handle, SOCKET_PATH)
    await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
