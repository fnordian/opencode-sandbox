"""Unit tests for the label-based exec authorization in podman-proxy.py.

The proxy injects a marker label into every container-create body that passes
through it, then checks for that label via an inspect round-trip before
allowing ``POST /containers/{id}/exec``.  Tests cover:

* ``inject_sandbox_label`` — label injection at create time.
* ``is_exec_request`` / ``extract_container_id`` — exec URL parsing.
* ``container_has_sandbox_label`` — label verification (with mocked upstream).
* ``forward_exec_if_allowed`` — end-to-end exec allow/deny (with mocks).

Run with::

    .venv/bin/python -m unittest tests.test_exec_label
"""

import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Load podman-proxy.py as a module (hyphen in filename → importlib)
_SPEC = importlib.util.spec_from_file_location(
    "podman_proxy",
    os.path.join(os.path.dirname(__file__), "..", "podman-proxy.py"),
)
_mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_mod)

# Shorthand references
inject_sandbox_label   = _mod.inject_sandbox_label
SANDBOX_LABEL          = _mod.SANDBOX_LABEL
is_exec_request        = _mod.is_exec_request
extract_container_id   = _mod.extract_container_id
container_has_sandbox_label = _mod.container_has_sandbox_label
forward_exec_if_allowed     = _mod.forward_exec_if_allowed


# =========================================================================
# Helpers
# =========================================================================

def _make_inspect_body(labels=None):
    """Build a typical podman inspect response dict, optionally with Labels."""
    body = {
        "Id": "abc123def456",
        "Config": {
            "Labels": labels or {},
        },
        "State": {"Running": True},
    }
    return body


def _mock_upstream(inspect_body, status=200):
    """Build a ``MagicMock`` that acts like a podman upstream socket.

    The mock's ``recv`` method returns a complete HTTP response containing
    *inspect_body* (encoded as JSON) with the given *status*.
    """
    body = json.dumps(inspect_body).encode()
    resp = (
        f"HTTP/1.1 {status} OK\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Content-Type: application/json\r\n"
        f"\r\n"
    ).encode() + body

    sock = MagicMock()
    # recv_until_double_crlf reads until \r\n\r\n is found;
    # return the full response on the first call, then empty.
    sock.recv.side_effect = [resp, b""]
    return sock


# =========================================================================
# inject_sandbox_label
# =========================================================================

class InjectSandboxLabelTest(unittest.TestCase):
    """inject_sandbox_label adds the marker label to create bodies."""

    def test_docker_compat_adds_labels(self):
        """Docker-compat body (has HostConfig): label goes into top-level Labels."""
        body = json.dumps({"Image": "nginx", "HostConfig": {}}).encode()
        result = json.loads(inject_sandbox_label(body))
        self.assertEqual(result.get("Labels", {}).get(SANDBOX_LABEL), "true")

    def test_docker_compat_merges_existing(self):
        """Existing Labels keys are preserved."""
        body = json.dumps({
            "Image": "nginx",
            "HostConfig": {},
            "Labels": {"my.label": "myvalue"},
        }).encode()
        result = json.loads(inject_sandbox_label(body))
        self.assertEqual(result["Labels"]["my.label"], "myvalue")
        self.assertEqual(result["Labels"][SANDBOX_LABEL], "true")

    def test_libpod_adds_labels(self):
        """Libpod body: label goes into top-level 'labels'."""
        body = json.dumps({"image": "nginx", "labels": {}}).encode()
        result = json.loads(inject_sandbox_label(body))
        self.assertEqual(result.get("labels", {}).get(SANDBOX_LABEL), "true")

    def test_libpod_merges_existing(self):
        """Existing libpod labels keys are preserved."""
        body = json.dumps({
            "image": "nginx",
            "labels": {"my.label": "myvalue"},
        }).encode()
        result = json.loads(inject_sandbox_label(body))
        self.assertEqual(result["labels"]["my.label"], "myvalue")
        self.assertEqual(result["labels"][SANDBOX_LABEL], "true")

    def test_both_shapes_get_label(self):
        """Both Labels and labels are populated regardless of which API the
        client used — podman ignores the irrelevant one."""
        body = json.dumps({"Image": "nginx", "HostConfig": {}}).encode()
        result = json.loads(inject_sandbox_label(body))
        self.assertEqual(result.get("Labels", {}).get(SANDBOX_LABEL), "true")
        self.assertEqual(result.get("labels", {}).get(SANDBOX_LABEL), "true")

    def test_non_json_passthrough(self):
        """Non-JSON bodies are returned unchanged (proxy never breaks them)."""
        original = b"not json"
        self.assertEqual(inject_sandbox_label(original), original)

    def test_non_dict_passthrough(self):
        """JSON array bodies are returned unchanged."""
        original = json.dumps(["a", "b"]).encode()
        self.assertEqual(inject_sandbox_label(original), original)


# =========================================================================
# is_exec_request / extract_container_id
# =========================================================================

class ExecRequestParsingTest(unittest.TestCase):
    """is_exec_request and extract_container_id parse exec URLs correctly."""

    def _headers(self, method, path):
        return f"{method} {path} HTTP/1.1\r\nHost: podman\r\n\r\n".encode()

    # -- is_exec_request ---------------------------------------------------

    def test_docker_compat_exec_request(self):
        self.assertTrue(is_exec_request(
            self._headers("POST", "/v3/containers/abc123/exec")))

    def test_libpod_exec_request(self):
        self.assertTrue(is_exec_request(
            self._headers("POST", "/libpod/containers/abc123/exec")))

    def test_unversioned_exec_request(self):
        self.assertTrue(is_exec_request(
            self._headers("POST", "/containers/abc123/exec")))

    def test_get_exec_is_not_exec(self):
        self.assertFalse(is_exec_request(
            self._headers("GET", "/containers/abc123/exec")))

    def test_create_not_exec(self):
        self.assertFalse(is_exec_request(
            self._headers("POST", "/containers/create")))

    def test_inspect_not_exec(self):
        self.assertFalse(is_exec_request(
            self._headers("GET", "/containers/abc123/json")))

    def test_start_not_exec(self):
        self.assertFalse(is_exec_request(
            self._headers("POST", "/exec/xyz789/start")))

    # -- extract_container_id ----------------------------------------------

    def test_extract_docker_compat(self):
        self.assertEqual(extract_container_id(
            self._headers("POST", "/v3/containers/abc123/exec")), "abc123")

    def test_extract_libpod(self):
        self.assertEqual(extract_container_id(
            self._headers("POST", "/libpod/containers/def456/exec")), "def456")

    def test_extract_unversioned(self):
        self.assertEqual(extract_container_id(
            self._headers("POST", "/containers/ghi789/exec")), "ghi789")

    def test_extract_none_for_non_exec(self):
        self.assertIsNone(extract_container_id(
            self._headers("POST", "/containers/create")))


# =========================================================================
# container_has_sandbox_label
# =========================================================================

class ContainerHasSandboxLabelTest(unittest.TestCase):
    """container_has_sandbox_label checks the marker label via inspect."""

    @patch.object(_mod.socket, 'socket')
    def test_label_present_docker_shape(self, mock_socket):
        """Label in Config.Labels → True."""
        mock_socket.return_value = _mock_upstream(
            _make_inspect_body(labels={SANDBOX_LABEL: "true"}))
        self.assertTrue(container_has_sandbox_label("abc123"))

    @patch.object(_mod.socket, 'socket')
    def test_label_present_libpod_fallback(self, mock_socket):
        """Label in top-level Labels (libpod shape) → True."""
        body = _make_inspect_body()  # Config.Labels empty
        body["Labels"] = {SANDBOX_LABEL: "true"}
        mock_socket.return_value = _mock_upstream(body)
        self.assertTrue(container_has_sandbox_label("abc123"))

    @patch.object(_mod.socket, 'socket')
    def test_label_absent(self, mock_socket):
        """No label anywhere → False."""
        mock_socket.return_value = _mock_upstream(_make_inspect_body(labels={}))
        self.assertFalse(container_has_sandbox_label("abc123"))

    @patch.object(_mod.socket, 'socket')
    def test_container_not_found(self, mock_socket):
        """404 from upstream → False (fail-closed)."""
        mock_socket.return_value = _mock_upstream(
            {"message": "not found"}, status=404)
        self.assertFalse(container_has_sandbox_label("abc123"))

    @patch.object(_mod.socket, 'socket')
    def test_connection_error(self, mock_socket):
        """Socket.connect failure → False (fail-closed)."""
        mock_socket.return_value.connect.side_effect = OSError("connection refused")
        self.assertFalse(container_has_sandbox_label("abc123"))

    @patch.object(_mod.socket, 'socket')
    def test_bad_json_response(self, mock_socket):
        """Non-JSON body → False (fail-closed)."""
        sock = MagicMock()
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 4\r\n"
            b"\r\n"
            b"not json"
        )
        sock.recv.side_effect = [resp, b""]
        mock_socket.return_value = sock
        self.assertFalse(container_has_sandbox_label("abc123"))


# =========================================================================
# forward_exec_if_allowed
# =========================================================================

class ForwardExecIfAllowedTest(unittest.TestCase):
    """forward_exec_if_allowed authorises or denies exec requests."""

    def _exec_headers(self):
        return (
            b"POST /containers/abc123/exec HTTP/1.1\r\n"
            b"Host: podman\r\n"
            b"Content-Length: 2\r\n"
            b"\r\n"
            b"{}"
        )

    def _exec_headers_no_cid(self):
        return (
            b"POST /containers//exec HTTP/1.1\r\n"
            b"Host: podman\r\n"
            b"Content-Length: 2\r\n"
            b"\r\n"
            b"{}"
        )

    # -- allowed -----------------------------------------------------------

    @patch.object(_mod, 'container_has_sandbox_label', return_value=True)
    @patch.object(_mod.socket, 'socket')
    def test_allowed_returns_upstream(self, mock_socket, mock_label):
        """When the label is present, forward_exec_if_allowed returns an
        upstream socket (the original exec request has been sent)."""
        up = MagicMock()
        mock_socket.return_value = up
        headers = self._exec_headers()
        head_part, _, body_part = headers.partition(b"\r\n\r\n")
        result = forward_exec_if_allowed(
            head_part + b"\r\n\r\n", body_part, MagicMock())
        self.assertIsNotNone(result)
        mock_label.assert_called_once_with("abc123")
        up.sendall.assert_called_once_with(headers)

    # -- denied ------------------------------------------------------------

    @patch.object(_mod, 'container_has_sandbox_label', return_value=False)
    def test_denied_returns_none_and_sends_403(self, mock_label):
        """When the label is absent, 403 is sent and None returned."""
        client = MagicMock()
        headers = self._exec_headers()
        head_part, _, body_part = headers.partition(b"\r\n\r\n")
        result = forward_exec_if_allowed(
            head_part + b"\r\n\r\n", body_part, client)
        self.assertIsNone(result)
        mock_label.assert_called_once_with("abc123")
        client.sendall.assert_called_once()
        sent = client.sendall.call_args[0][0]
        self.assertIn(b"403 Forbidden", sent)
        self.assertIn(b"sandbox proxy", sent)

    # -- malformed ---------------------------------------------------------

    def test_malformed_cid_returns_none(self):
        """When no container ID can be extracted, 403 is sent."""
        client = MagicMock()
        headers = self._exec_headers_no_cid()
        head_part, _, body_part = headers.partition(b"\r\n\r\n")
        result = forward_exec_if_allowed(
            head_part + b"\r\n\r\n", body_part, client)
        self.assertIsNone(result)
        client.sendall.assert_called_once()
        self.assertIn(b"malformed", client.sendall.call_args[0][0])


if __name__ == "__main__":
    unittest.main()
