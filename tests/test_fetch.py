import contextlib
import gc
import socket
import threading
import unittest
import urllib.error
import warnings
from http.server import BaseHTTPRequestHandler, HTTPServer

from webposture import cookies, fetch, runner, transport
from webposture.cookies import SetCookie
from webposture.fetch import fetch_final_url, fetch_headers
from webposture.headermap import HeaderMap


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


class _Chain(BaseHTTPRequestHandler):
    """/start redirects to /final with a cookie; /final sets its own and repeats a header."""

    def do_GET(self):
        if self.path == "/start":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.send_header("Set-Cookie", "session=abc; Path=/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/p308":
            # Python 3.9 and 3.10 do not follow 308 on their own.
            self.send_response(308)
            self.send_header("Location", "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/missing":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/no-location":
            self.send_response(302)
            self.send_header("X-Marker", "kept")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Set-Cookie", "prefs=dark; Path=/; HttpOnly; SameSite=Lax")
        self.send_header("Content-Security-Policy", "script-src 'self'")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class _LocalServerTest(unittest.TestCase):
    def _serve(self, handler):
        server = HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def _redirect_to(self, target):
        return self._serve(type("Handler", (_Redirect,), {"target": target})) + "/"


class FetchFinalUrlTest(_LocalServerTest):
    """Runs against a local server only, no internet access needed."""

    def test_redirect_to_failing_https_target_is_still_reported(self):
        # The HTTPS side failing (here: nothing listening, in real life often a
        # bad certificate) must not turn a real redirect into "not reachable".
        target = f"https://127.0.0.1:{_closed_port()}/"
        self.assertEqual(fetch_final_url(self._redirect_to(target), timeout=5), target)

    def test_nothing_listening_returns_none(self):
        self.assertIsNone(fetch_final_url(f"http://127.0.0.1:{_closed_port()}/", timeout=5))

    def test_a_redirect_to_another_scheme_is_reported_not_followed(self):
        target = "ftp://127.0.0.1/internal"
        final = fetch_final_url(self._redirect_to(target), timeout=5)
        self.assertEqual(final, target)
        finding = transport.check_https_redirect("http://example.test/", final)
        self.assertEqual(finding.status, "FAIL")
        self.assertIn("which is not HTTPS", finding.detail)


class FetchHeadersTest(_LocalServerTest):
    def test_cookies_from_every_hop_are_collected_with_the_url_that_set_them(self):
        base = self._serve(_Chain)
        result = fetch_headers(base + "/start", timeout=5)
        self.assertEqual(result.url, base + "/final")
        self.assertEqual(result.cookies, [SetCookie("session=abc; Path=/", base + "/start", redirect=True),
                                          SetCookie("prefs=dark; Path=/; HttpOnly; SameSite=Lax", base + "/final")])
        finding = cookies.check_cookies(result.cookies, is_https=False)
        self.assertEqual(finding.status, "WARN")
        self.assertIn(f"session (set by the redirect at {base}/start): missing HttpOnly", finding.detail)

    def test_repeated_headers_reach_the_checks(self):
        result = fetch_headers(self._serve(_Chain) + "/final", timeout=5)
        self.assertEqual(result.headers.get_all("content-security-policy"), ["script-src 'self'", "frame-ancestors 'none'"])
        # Still unpacks like the old 4-tuple.
        _url, _headers, _cookies, status = result
        self.assertEqual(status, 200)

    def test_redirect_loop_is_a_fetch_error(self):
        with self.assertRaises(urllib.error.URLError) as caught:
            fetch_headers(self._serve(_Chain) + "/loop", timeout=5)
        self.assertIn("redirect loop", str(caught.exception.reason))

    def test_error_pages_and_failed_redirects_release_their_connection(self):
        # urllib raises an HTTPError that holds the open response; it must be
        # closed, or each such request leaves a socket open until it is collected.
        base = self._serve(_Chain)
        calls = {
            "headers of a 404": lambda: fetch_headers(base + "/missing", timeout=5),
            "headers after a loop": lambda: fetch_headers(base + "/loop", timeout=5),
            "headers after a refused redirect": lambda: fetch_headers(self._redirect_to("file:///etc/passwd"), timeout=5),
            "text of a 404": lambda: fetch.fetch_text(base + "/missing", 5, 1024),
            "text after a loop": lambda: fetch.fetch_text(base + "/loop", 5, 1024),
            "final URL of a 404": lambda: fetch_final_url(base + "/missing", timeout=5),
            "final URL after a loop": lambda: fetch_final_url(base + "/loop", timeout=5),
        }
        for name, call in calls.items():
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", ResourceWarning)
                with contextlib.suppress(urllib.error.URLError):
                    call()
                gc.collect()
            self.assertEqual([str(w.message) for w in caught if w.category is ResourceWarning], [], name)

    def test_308_is_followed_on_every_python(self):
        base = self._serve(_Chain)
        fetched = fetch_headers(base + "/p308", timeout=5)
        self.assertEqual((fetched.url, fetched.status), (base + "/final", 200))
        self.assertEqual(fetch_final_url(base + "/p308", timeout=5), base + "/final")

    def test_a_redirect_without_location_is_the_final_response(self):
        result = fetch_headers(self._serve(_Chain) + "/no-location", timeout=5)
        self.assertEqual((result.status, result.headers.get("X-Marker")), (302, "kept"))

    def test_a_redirect_to_another_scheme_is_refused(self):
        with self.assertRaises(urllib.error.URLError) as caught:
            fetch_headers(self._redirect_to("file:///etc/passwd"), timeout=5)
        self.assertIn("not an http(s) URL", str(caught.exception.reason))

    def test_security_txt_behind_a_refused_redirect_is_not_fetched(self):
        self.assertEqual(fetch.fetch_text(self._redirect_to("ftp://127.0.0.1/security.txt"), 5, 1024), (None, None, ""))

    def test_only_http_and_https_targets_are_fetched(self):
        for url in ("file:///etc/passwd", "ftp://127.0.0.1/", "data:text/plain,hi"):
            with self.assertRaises(urllib.error.URLError, msg=url):
                fetch_headers(url, timeout=5)
            self.assertEqual(fetch.fetch_text(url, 5, 1024), (None, None, ""), url)


class MalformedResponseTest(unittest.TestCase):
    def _garbage_server(self, connections=1):
        """A server that answers each connection with something that is not HTTP."""
        listener = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(listener.close)

        def answer():
            for _ in range(connections):
                conn, _ = listener.accept()
                with conn:
                    conn.recv(1024)
                    conn.sendall(b"NOT HTTP AT ALL\r\n\r\n")

        threading.Thread(target=answer, daemon=True).start()
        return f"http://127.0.0.1:{listener.getsockname()[1]}/"

    def test_a_garbled_response_is_explained(self):
        url = self._garbage_server()
        with self.assertRaises(fetch.FETCH_ERRORS) as caught:
            fetch_headers(url, timeout=5)
        message = fetch.describe_fetch_error(url, caught.exception, 5, 1)
        self.assertIn("malformed response", message)
        self.assertIn("BadStatusLine", message)

    def test_an_unreadable_plain_http_answer_is_not_nothing(self):
        # Something answered on plain HTTP, so https-redirect must not pass as "not reachable".
        url = self._garbage_server()
        with self.assertRaises(fetch.UNREADABLE):
            fetch_final_url(url, timeout=5)
        finding = runner.check_https_redirect(self._garbage_server(), 5)
        self.assertEqual((finding.check, finding.status), ("https-redirect", "WARN"))
        self.assertIn("answered with a response that could not be read (BadStatusLine", finding.detail)

    def test_an_unreadable_answer_after_a_redirect_still_reports_the_redirect(self):
        garbage = self._garbage_server()
        listener = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(listener.close)

        def redirect():
            conn, _ = listener.accept()
            with conn:
                conn.recv(1024)
                conn.sendall(f"HTTP/1.1 302 Found\r\nLocation: {garbage}\r\nContent-Length: 0\r\n\r\n".encode())

        threading.Thread(target=redirect, daemon=True).start()
        self.assertEqual(fetch_final_url(f"http://127.0.0.1:{listener.getsockname()[1]}/", timeout=5), garbage)


class CorsProbeTest(unittest.TestCase):
    def test_repeated_allow_origin_is_combined_so_it_is_not_a_match(self):
        # Fetch combines repeated headers: "x, x" is not the origin x, so browsers deny access.
        probe = fetch.FetchResult("https://example.com/", HeaderMap([
            ("Access-Control-Allow-Origin", "https://web-posture-check.invalid"),
            ("Access-Control-Allow-Origin", "https://web-posture-check.invalid"),
            ("Access-Control-Allow-Credentials", "true")]), [], 200)
        from unittest import mock
        with mock.patch.object(fetch, "fetch_headers", return_value=probe):
            self.assertEqual(runner.probe_cors("https://example.com/", 5).status, "PASS")


if __name__ == "__main__":
    unittest.main()
