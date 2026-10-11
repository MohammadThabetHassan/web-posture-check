import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from webposture.fetch import fetch_final_url


def _closed_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Redirect(BaseHTTPRequestHandler):
    target = ""

    def do_GET(self):
        self.send_response(301)
        self.send_header("Location", self.target)
        self.end_headers()

    def log_message(self, *args):
        pass


class FetchFinalUrlTest(unittest.TestCase):
    """Runs against a local server only, no internet access needed."""

    def _serve(self, target):
        handler = type("Handler", (_Redirect,), {"target": target})
        server = HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}/"

    def test_redirect_to_failing_https_target_is_still_reported(self):
        # The HTTPS side failing (here: nothing listening, in real life often a
        # bad certificate) must not turn a real redirect into "not reachable".
        target = f"https://127.0.0.1:{_closed_port()}/"
        self.assertEqual(fetch_final_url(self._serve(target), timeout=5), target)

    def test_nothing_listening_returns_none(self):
        self.assertIsNone(fetch_final_url(f"http://127.0.0.1:{_closed_port()}/", timeout=5))


if __name__ == "__main__":
    unittest.main()
