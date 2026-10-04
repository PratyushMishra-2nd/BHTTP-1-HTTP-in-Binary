"""Unit tests for bcurl against a scripted fake server.

The fake server is a few lines of socket code that replays exact bytes, so
these tests cover what a correct server never sends: oversized frames,
stream 0, ERROR frames, truncation, noise and one-byte delivery.

    python -m unittest discover -s tests -v
"""

import io
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import bcurl  # noqa: E402


def frame(ftype, flags, stream_id, payload=b"", reserved=0, length=None):
    n = len(payload) if length is None else length
    return struct.pack(">IBBHI", n, ftype, flags, reserved, stream_id) + payload


def hdr(hid, value):
    return struct.pack(">BH", hid, len(value)) + value


def custom(name, value):
    return struct.pack(">BH", 0, len(name)) + name + struct.pack(">H", len(value)) + value


def response(stream_id, status, headers, end=False, flags=None):
    payload = struct.pack(">HB", status, len(headers)) + b"".join(headers)
    f = (bcurl.END_STREAM if end else 0) if flags is None else flags
    return frame(bcurl.T_RESPONSE, f, stream_id, payload)


def ok(stream_id, body, extra_headers=()):
    """A well-formed 200 exchange, split into 16384-byte DATA frames."""
    headers = [hdr(1, b"application/octet-stream"), hdr(2, str(len(body)).encode())] + list(extra_headers)
    out = response(stream_id, 200, headers, end=not body)
    for off in range(0, len(body), 16384):
        last = off + 16384 >= len(body)
        out += frame(bcurl.T_DATA, bcurl.END_STREAM if last else 0, stream_id, body[off:off + 16384])
    return out


def read_frame(sock):
    def exact(n):
        buf = b""
        while len(buf) < n:
            c = sock.recv(n - len(buf))
            if not c:
                return None
            buf += c
        return buf
    h = exact(12)
    if h is None:
        return None
    length = struct.unpack(">I", h[:4])[0]
    return h, exact(length) if length else b""


class FakeServer:
    """Accepts connections; for each REQUEST it reads, sends script[i](stream_id)."""

    def __init__(self, script, chunk=None, close_after=False):
        self.script = list(script)
        self.chunk = chunk
        self.close_after = close_after
        self.requests = []
        self.received_after = []   # frames read after the script ran out (e.g. an ERROR from the client)
        self.connections = 0
        self.lsock = socket.socket()
        self.lsock.bind(("127.0.0.1", 0))
        self.lsock.listen(4)
        self.port = self.lsock.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def send(self, conn, data):
        if not self.chunk:
            conn.sendall(data)
            return
        for i in range(0, len(data), self.chunk):
            conn.sendall(data[i:i + self.chunk])
            time.sleep(0.0005)

    def serve(self):
        self.lsock.settimeout(5)
        try:
            conn, _ = self.lsock.accept()
        except OSError:
            return
        self.connections += 1
        conn.settimeout(5)
        with conn:
            try:
                while self.script:
                    f = read_frame(conn)
                    if f is None:
                        return
                    self.requests.append(f)
                    stream_id = struct.unpack(">I", f[0][8:12])[0]
                    step = self.script.pop(0)
                    self.send(conn, step(stream_id) if callable(step) else step)
                if self.close_after:
                    return
                while True:
                    f = read_frame(conn)
                    if f is None:
                        return
                    self.received_after.append(f)
            except OSError:
                return

    def close(self):
        self.thread.join(5)
        # A client that reconnected would be sitting in the backlog now.
        self.lsock.settimeout(0.1)
        try:
            self.lsock.accept()[0].close()
            self.connections += 1
        except OSError:
            pass
        self.lsock.close()


def run(args, port, timeout="3"):
    out, err = io.BytesIO(), io.StringIO()
    argv = ["-t", timeout] + [a.replace("PORT", str(port)) for a in args]
    code = bcurl.run(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


class EncodingTests(unittest.TestCase):
    def test_request_matches_reference_capture(self):
        # INTEROP_GUIDE §5: GET /index.html, stream 1, no headers.
        payload = bcurl.encode_request(b"/index.html", [])
        wire = bcurl.frame_header(len(payload), bcurl.T_REQUEST, bcurl.END_STREAM, 1) + payload
        self.assertEqual(wire.hex(" ").upper(),
                         "00 00 00 0F 01 01 00 00 00 00 00 01 01 00 0B 2F 69 6E 64 65 78 2E 68 74 6D 6C 00")

    def test_table_header_sent_by_id(self):
        name, value = bcurl.parse_header_arg("Content-Type: text/plain")
        self.assertEqual(bcurl.encode_header(name, value), b"\x01\x00\x0atext/plain")

    def test_custom_header_lowercased(self):
        name, value = bcurl.parse_header_arg("X-Demo:  hello")
        self.assertEqual(bcurl.encode_header(name, value), b"\x00\x00\x06x-demo\x00\x05hello")

    def test_bad_custom_name_refused_locally(self):
        with self.assertRaises(bcurl.UsageError):
            bcurl.parse_header_arg("bad name: x")

    def test_utf8_path_is_not_percent_encoded(self):
        _, _, path = bcurl.split_target("localhost:9000/unicode/naïve.txt")
        self.assertIn(b"\x6E\x61\xC3\xAF\x76\x65", path)

    def test_odd_paths_sent_unmodified(self):
        for p in ["/a:b", "/../x", "/a\\b", "//x", "/con", "/index.html."]:
            self.assertEqual(bcurl.split_target("h:1" + p)[2], p.encode())

    def test_target_forms(self):
        self.assertEqual(bcurl.split_target("localhost:9000"), ("localhost", 9000, b"/"))
        self.assertEqual(bcurl.split_target("bhttp://[::1]:9000/x"), ("::1", 9000, b"/x"))
        with self.assertRaises(bcurl.UsageError):
            bcurl.split_target("localhost/x")

    def test_oversized_request_refused(self):
        with self.assertRaises(bcurl.UsageError):
            bcurl.encode_request(b"/" + b"a" * 4096, [])


class ResponseTests(unittest.TestCase):
    def fetch(self, script, args=("127.0.0.1:PORT/f",), **kw):
        srv = FakeServer(script, **kw)
        try:
            return run(list(args), srv.port) + (srv,)
        finally:
            srv.close()

    def test_body_and_exit_zero(self):
        body = bytes(range(256)) + b"\r\n\x00\r\n"
        code, out, _, _ = self.fetch([lambda s: ok(s, body)])
        self.assertEqual((code, out), (0, body))

    def test_frame_boundaries(self):
        for size in (16383, 16384, 16385, 65536):
            body = bytes(i % 251 for i in range(size))
            code, out, _, _ = self.fetch([lambda s, b=body: ok(s, b)])
            self.assertEqual((code, out), (0, body), size)

    def test_one_byte_delivery(self):
        body = bytes(i % 251 for i in range(16385))
        code, out, _, _ = self.fetch([lambda s: ok(s, body)], chunk=1)
        self.assertEqual((code, out), (0, body))

    def test_empty_body_ends_on_response(self):
        code, out, _, _ = self.fetch([lambda s: response(s, 200, [hdr(2, b"0")], end=True)])
        self.assertEqual((code, out), (0, b""))

    def test_unknown_frames_skipped_without_inspection(self):
        noise = lambda: (frame(5, 0xFF, 0, b"zz", reserved=0xBEEF) + frame(255, 0x7E, 99, b"")
                         + frame(128, 0, 0, b"x" * 16384))
        script = [lambda s: noise() + response(s, 200, [hdr(2, b"3")]) + noise()
                  + frame(3, 1, s, b"abc") + noise()]
        code, out, _, _ = self.fetch(script)
        self.assertEqual((code, out), (0, b"abc"))

    def test_undefined_flags_and_reserved_ignored(self):
        script = [lambda s: response(s, 200, [], flags=0xFE) + frame(3, 0xFF, s, b"hi", reserved=7)]
        code, out, _, _ = self.fetch(script)
        self.assertEqual((code, out), (0, b"hi"))

    def test_empty_data_frames_tolerated(self):
        script = [lambda s: response(s, 200, [hdr(2, b"2")]) + frame(3, 0, s) + frame(3, 0, s, b"hi")
                  + frame(3, 1, s)]
        code, out, _, _ = self.fetch(script)
        self.assertEqual((code, out), (0, b"hi"))

    def test_unknown_header_ids_and_custom_headers_ignored(self):
        script = [lambda s: response(s, 200, [hdr(9, b"x"), hdr(255, b""), custom(b"X Y", b"v"),
                                              hdr(2, b"0002"), hdr(2, b"2")])
                  + frame(3, 1, s, b"ok")]
        code, out, _, _ = self.fetch(script)
        self.assertEqual((code, out), (0, b"ok"))

    def test_404_and_400_exit_1(self):
        for status in (400, 404, 500):
            code, _, err, _ = self.fetch([lambda s, st=status: response(s, st, [hdr(2, b"0")], end=True)])
            self.assertEqual(code, 1)
            self.assertIn("-> %d" % status, err)

    def test_3xx_not_an_error(self):
        code, _, _, _ = self.fetch([lambda s: response(s, 301, [], end=True)])
        self.assertEqual(code, 0)

    def test_one_connection_increasing_stream_ids(self):
        script = [lambda s: ok(s, b"a"), lambda s: response(s, 404, [hdr(2, b"0")], end=True),
                  lambda s: ok(s, b"c")]
        code, out, _, srv = self.fetch(script, args=("127.0.0.1:PORT/1", "/2", "127.0.0.1:PORT/3"))
        self.assertEqual((code, out), (1, b"ac"))
        ids = [struct.unpack(">I", h[8:12])[0] for h, _ in srv.requests]
        self.assertEqual(ids, [1, 2, 3])
        self.assertEqual(srv.connections, 1)

    def test_request_frame_on_wire(self):
        _, _, _, srv = self.fetch([lambda s: ok(s, b"")], args=("-H", "x-demo: hello", "127.0.0.1:PORT/p"))
        h, p = srv.requests[0]
        self.assertEqual(h, bytes.fromhex("00000016 01 01 0000 00000001"))
        self.assertEqual(p, b"\x01\x00\x02/p\x01\x00\x00\x06x-demo\x00\x05hello")

    # --- failures: exit 3, and nothing is sent back unless SPEC §4 says so

    def assertFails(self, script, needle, **kw):
        code, _, err, srv = self.fetch(script, **kw)
        self.assertEqual(code, 3, err)
        self.assertIn(needle, err)
        return srv

    def test_content_length_mismatch(self):
        self.assertFails([lambda s: response(s, 200, [hdr(2, b"5")]) + frame(3, 1, s, b"abc")], "content-length")

    def test_content_length_not_digits(self):
        self.assertFails([lambda s: response(s, 200, [hdr(2, b"+3")]) + frame(3, 1, s, b"abc")], "digits")

    def test_data_before_response(self):
        self.assertFails([lambda s: frame(3, 1, s, b"x")], "DATA before RESPONSE")

    def test_wrong_stream(self):
        self.assertFails([lambda s: response(s + 1, 200, [], end=True)], "while waiting for stream")

    def test_second_response(self):
        self.assertFails([lambda s: response(s, 200, []) + response(s, 200, [], end=True)], "second RESPONSE")

    def test_status_out_of_range(self):
        self.assertFails([lambda s: response(s, 600, [], end=True)], "outside 100-599")

    def test_trailing_bytes_in_response(self):
        self.assertFails([lambda s: frame(2, 1, s, b"\x00\xc8\x00!")], "after its last header")

    def test_header_past_payload(self):
        self.assertFails([lambda s: frame(2, 1, s, b"\x00\xc8\x01\x02\x00\x05ab")], "runs past")

    def test_eof_before_end_stream(self):
        self.assertFails([lambda s: response(s, 200, [hdr(2, b"3")]) + frame(3, 0, s, b"ab")],
                         "before END_STREAM", close_after=True)

    def test_truncated_frame(self):
        self.assertFails([lambda s: frame(3, 1, s, b"abc", length=10)], "inside a frame", close_after=True)

    def test_error_frame_closes_without_reply(self):
        err = struct.pack(">HH", 3, 4) + b"oops"
        srv = self.assertFails([frame(4, 0, 0, err)], "PROTOCOL_ERROR")
        self.assertEqual(srv.received_after, [])

    def test_frame_too_large_sends_error_1(self):
        srv = self.assertFails([frame(3, 0, 1, b"", length=16385)], "FRAME_TOO_LARGE")
        self.assertEqual(len(srv.received_after), 1)
        h, p = srv.received_after[0]
        self.assertEqual((h[4], h[8:12], p[:2]), (4, b"\0\0\0\0", b"\x00\x01"))

    def test_unknown_type_too_large_is_still_fault(self):
        self.assertFails([frame(9, 0, 0, b"", length=0x47455420)], "FRAME_TOO_LARGE")

    def test_oversized_error_just_closes(self):
        srv = self.assertFails([frame(4, 0, 0, b"", length=20000)], "oversized ERROR")
        self.assertEqual(srv.received_after, [])

    def test_stream_zero_sends_error_2(self):
        srv = self.assertFails([response(0, 200, [], end=True)], "INVALID_STREAM_ID")
        self.assertEqual(srv.received_after[0][1][:2], b"\x00\x02")

    def test_request_at_client_sends_error_3(self):
        srv = self.assertFails([frame(1, 1, 1, b"\x01\x00\x01/\x00")], "REQUEST received")
        self.assertEqual(srv.received_after[0][1][:2], b"\x00\x03")

    def test_failure_stops_further_requests(self):
        _, _, _, srv = self.fetch([lambda s: frame(3, 1, s, b"x"), lambda s: ok(s, b"y")],
                                  args=("127.0.0.1:PORT/a", "/b"))
        self.assertEqual(len(srv.requests), 1)

    def test_output_file_only_on_success(self):
        d = tempfile.mkdtemp()
        good, bad = os.path.join(d, "good"), os.path.join(d, "bad")
        self.fetch([lambda s: ok(s, b"body")], args=("-o", good, "127.0.0.1:PORT/f"))
        self.fetch([lambda s: frame(3, 1, s, b"x")], args=("-o", bad, "127.0.0.1:PORT/f"))
        with open(good, "rb") as f:
            self.assertEqual(f.read(), b"body")
        self.assertFalse(os.path.exists(bad) or os.path.exists(bad + ".part"))

    def test_timeout(self):
        srv = FakeServer([b""])
        try:
            code, _, err = run(["127.0.0.1:PORT/f"], srv.port, timeout="0.3")
        finally:
            srv.close()
        self.assertEqual(code, 3)
        self.assertIn("timed out", err)

    def test_verbose_dumps_every_frame(self):
        script = [lambda s: frame(6, 0, 0, b"n") + ok(s, b"hi")]
        code, _, err, _ = self.fetch(script, args=("-v", "127.0.0.1:PORT/f"))
        self.assertEqual(code, 0)
        self.assertIn("--> frame 1  REQUEST  stream=1  flags=END_STREAM", err)
        self.assertIn("<-- frame 2  UNKNOWN(0x06)", err)
        self.assertIn("<-- frame 3  RESPONSE", err)
        self.assertIn("<-- frame 4  DATA  stream=1  flags=END_STREAM  length=2", err)


class UsageTests(unittest.TestCase):
    def test_usage_errors_exit_2(self):
        for argv in ([], ["/x"], ["h:1/a", "g:1/b"], ["-o", "f", "h:1/a", "/b"], ["-H", "nocolon", "h:1/"],
                     ["--bogus", "h:1/"], ["h/x"]):
            self.assertEqual(bcurl.run(argv, stdout=io.BytesIO(), stderr=io.StringIO()), 2, argv)

    def test_connection_refused_exit_3(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertEqual(run(["127.0.0.1:PORT/x"], port)[0], 3)


if __name__ == "__main__":
    unittest.main()
