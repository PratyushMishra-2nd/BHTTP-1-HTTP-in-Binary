#!/usr/bin/env python3
"""bcurl - a BHTTP/1 client (Track 2).

Written from the BHTTP/1 specification alone (protocol/SPEC.md,
protocol/WIRE_FORMAT.md, protocol/HEADER_TABLE.md). It shares no code with
any server it talks to.

    bcurl [-v] [-H "name: value"]... [-o FILE] [-t SECONDS] HOST:PORT/PATH [/PATH ...]

Every PATH given on the command line is fetched in order over ONE TCP
connection, using stream IDs 1, 2, 3, ...  Bodies go to stdout (or -o FILE),
byte for byte. With -v every frame in both directions is hexdumped to stderr,
built from the exact bytes that were written to or read from the socket.

Exit status:
    0  every response was 100-399
    1  at least one response was 4xx or 5xx (and nothing failed)
    2  bad usage (nothing was sent)
    3  an exchange failed: connection error, ERROR frame, truncation,
       or a response that breaks the protocol
"""

import os
import socket
import struct
import sys
import time

# ---------------------------------------------------------------------------
# Wire constants (WIRE_FORMAT.md §2-§9, HEADER_TABLE.md §1)

HEADER_LEN = 12
MAX_PAYLOAD = 16384
MAX_PATH = 4096

T_REQUEST, T_RESPONSE, T_DATA, T_ERROR = 1, 2, 3, 4
KNOWN_TYPES = {T_REQUEST: "REQUEST", T_RESPONSE: "RESPONSE", T_DATA: "DATA", T_ERROR: "ERROR"}

END_STREAM = 0x01
METHOD_GET = 0x01

ERR_FRAME_TOO_LARGE, ERR_INVALID_STREAM_ID, ERR_PROTOCOL = 1, 2, 3
ERROR_NAMES = {1: "FRAME_TOO_LARGE", 2: "INVALID_STREAM_ID", 3: "PROTOCOL_ERROR"}

HEADER_TABLE = {
    1: "content-type",
    2: "content-length",
    3: "server",
    4: "date",
    5: "connection",
    6: "content-encoding",
    7: "cache-control",
    8: "last-modified",
}
HEADER_IDS = {name: hid for hid, name in HEADER_TABLE.items()}
CUSTOM_NAME_CHARS = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789-_.")

MAX_STREAM_ID = 0xFFFFFFFF

EXIT_OK, EXIT_HTTP_ERROR, EXIT_USAGE, EXIT_FAILED = 0, 1, 2, 3

# Bounded drain after sending an ERROR (SPEC §9 rule 3).
DRAIN_SECONDS = 1.0
DRAIN_BYTES = 64 * 1024


class UsageError(Exception):
    """Bad command line; nothing has been sent."""


class ExchangeFailed(Exception):
    """The exchange cannot complete; the connection must be closed (SPEC §12.8)."""


class PeerError(ExchangeFailed):
    """The server sent an ERROR frame."""


class ConnectionFault(ExchangeFailed):
    """A §4 step 2/5 fault (or a REQUEST at the client): we owe the peer an ERROR."""

    def __init__(self, code, message):
        super().__init__("%s: %s" % (ERROR_NAMES[code], message))
        self.code = code
        self.wire_message = message


# ---------------------------------------------------------------------------
# Encoding

def frame_header(length, ftype, flags, stream_id):
    """12-byte frame header: Length u32 | Type u8 | Flags u8 | Reserved u16 | Stream ID u32."""
    return struct.pack(">IBBHI", length, ftype, flags, 0, stream_id)


def encode_header(name, value):
    """One header (WIRE_FORMAT §7). Table names are always sent by ID."""
    if len(value) > 0xFFFF:
        raise UsageError("header value for %r is longer than 65535 bytes" % name)
    hid = HEADER_IDS.get(name)
    if hid is not None:
        return struct.pack(">BH", hid, len(value)) + value
    raw = name.encode("ascii")
    return struct.pack(">BH", 0, len(raw)) + raw + struct.pack(">H", len(value)) + value


def encode_request(path, headers):
    """REQUEST payload (WIRE_FORMAT §5): Method | Path Length | Path | Header Count | Headers."""
    if not 1 <= len(path) <= MAX_PATH:
        raise UsageError("path must be 1 to %d bytes, got %d" % (MAX_PATH, len(path)))
    if len(headers) > 255:
        raise UsageError("at most 255 request headers")
    payload = bytearray()
    payload += struct.pack(">BH", METHOD_GET, len(path))
    payload += path
    payload += struct.pack(">B", len(headers))
    for name, value in headers:
        payload += encode_header(name, value)
    if len(payload) > MAX_PAYLOAD:
        raise UsageError("request is %d bytes; one frame holds at most %d" % (len(payload), MAX_PAYLOAD))
    return bytes(payload)


def encode_error(code, message):
    msg = message.encode("utf-8")
    payload = struct.pack(">HH", code, len(msg)) + msg
    return frame_header(len(payload), T_ERROR, 0, 0) + payload


def parse_header_arg(text):
    """-H "Name: value" -> (name, value bytes). Names are lowercased; HEADER_TABLE §2.3."""
    if ":" not in text:
        raise UsageError("header %r must look like 'name: value'" % text)
    name, _, value = text.partition(":")
    name = name.strip().lower()
    if not name:
        raise UsageError("header %r has an empty name" % text)
    if name not in HEADER_IDS:
        raw = name.encode("ascii", "replace")
        if len(raw) > 255 or any(b not in CUSTOM_NAME_CHARS for b in raw):
            raise UsageError("header name %r: custom names are 1-255 bytes of a-z 0-9 - _ ." % name)
    return name, value.lstrip(" \t").encode("utf-8", "surrogateescape")


# ---------------------------------------------------------------------------
# Decoding a RESPONSE payload (WIRE_FORMAT §6-§7, SPEC §12.6-§12.7)

def decode_response(payload):
    """Return (status, [(id, name, value)]). Raises ExchangeFailed if malformed."""
    if len(payload) < 3:
        raise ExchangeFailed("RESPONSE payload is %d bytes; at least 3 are required" % len(payload))
    status, count = struct.unpack_from(">HB", payload, 0)
    pos = 3
    headers = []
    for i in range(count):
        def need(n, what):
            if pos + n > len(payload):
                raise ExchangeFailed("RESPONSE header %d: %s runs past the end of the payload" % (i + 1, what))
        need(1, "header ID")
        hid = payload[pos]
        pos += 1
        if hid == 0:
            need(2, "name length")
            (nlen,) = struct.unpack_from(">H", payload, pos)
            pos += 2
            if not 1 <= nlen <= 255:
                raise ExchangeFailed("RESPONSE header %d: custom name length %d is outside 1-255" % (i + 1, nlen))
            need(nlen, "name")
            name = payload[pos:pos + nlen].decode("ascii", "replace")
            pos += nlen
        else:
            # IDs 9-255 are unknown in v1: same layout, parsed and ignored (SPEC §7.4).
            name = HEADER_TABLE.get(hid)
        need(2, "value length")
        (vlen,) = struct.unpack_from(">H", payload, pos)
        pos += 2
        need(vlen, "value")
        headers.append((hid, name, payload[pos:pos + vlen]))
        pos += vlen
    if pos != len(payload):
        raise ExchangeFailed("RESPONSE has %d bytes after its last header" % (len(payload) - pos))
    if not 100 <= status <= 599:
        raise ExchangeFailed("RESPONSE status %d is outside 100-599" % status)
    return status, headers


def content_lengths(headers):
    """Every content-length value as an int; malformed values fail the response (SPEC §12.5)."""
    out = []
    for hid, _name, value in headers:
        if hid != HEADER_IDS["content-length"]:
            continue
        if not 1 <= len(value) <= 19 or not all(0x30 <= b <= 0x39 for b in value):
            raise ExchangeFailed("content-length %r is not 1-19 ASCII digits" % value)
        out.append(int(value))
    return out


# ---------------------------------------------------------------------------
# Verbose output: every frame, from the bytes that actually crossed the socket

def hexdump(data, indent="      "):
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexes = " ".join("%02X" % b for b in chunk[:8])
        if len(chunk) > 8:
            hexes += "  " + " ".join("%02X" % b for b in chunk[8:])
        text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append("%s%08X  %-49s |%s|" % (indent, off, hexes, text))
    return "\n".join(lines)


def describe_flags(flags):
    if flags == 0:
        return "none"
    parts = []
    if flags & END_STREAM:
        parts.append("END_STREAM")
    if flags & ~END_STREAM & 0xFF:
        parts.append("0x%02X" % (flags & ~END_STREAM & 0xFF))
    return "|".join(parts)


class Trace:
    """Writes the -v hexdump. Disabled tracing costs nothing."""

    def __init__(self, enabled, out=None):
        self.enabled = enabled
        self.out = out if out is not None else sys.stderr
        self.count = 0

    def note(self, text):
        if self.enabled:
            self.out.write("*   %s\n" % text)
            self.out.flush()

    def frame(self, direction, header, payload, extra=None):
        if not self.enabled:
            return
        self.count += 1
        length, ftype, flags, reserved, stream_id = struct.unpack(">IBBHI", header)
        name = KNOWN_TYPES.get(ftype, "UNKNOWN(0x%02X)" % ftype)
        w = self.out.write
        if ftype in KNOWN_TYPES:
            w("%s frame %d  %s  stream=%d  flags=%s  length=%d\n"
              % (direction, self.count, name, stream_id, describe_flags(flags), length))
        else:
            # Flags, Reserved and Stream ID of an unknown frame carry no meaning.
            w("%s frame %d  %s  length=%d  (unknown type: skipped by length)\n"
              % (direction, self.count, name, length))
        w("    header   %s\n" % " ".join("%02X" % b for b in header))
        if reserved and ftype in KNOWN_TYPES:
            w("    note     Reserved=0x%04X (ignored)\n" % reserved)
        if payload is not None and len(payload):
            w("    payload\n%s\n" % hexdump(payload))
        if extra:
            for line in extra:
                w("    %s\n" % line)
        self.out.flush()

    def partial(self, direction, data, what):
        if not self.enabled:
            return
        self.out.write("%s truncated %s: %d bytes before EOF\n" % (direction, what, len(data)))
        if data:
            self.out.write(hexdump(data) + "\n")
        self.out.flush()


def show(value):
    return value.decode("utf-8", "backslashreplace")


def describe_request(path, headers):
    lines = ["decoded  method=GET  path=%s  headers=%d" % (show(path), len(headers))]
    for name, value in headers:
        hid = HEADER_IDS.get(name, 0)
        lines.append("         [id %d] %s: %s" % (hid, name, show(value)))
    return lines


def describe_response(status, headers):
    lines = ["decoded  status=%d  headers=%d" % (status, len(headers))]
    for hid, name, value in headers:
        label = name if name is not None else "(unknown id, ignored)"
        lines.append("         [id %d] %s: %s" % (hid, label, show(value)))
    return lines


# ---------------------------------------------------------------------------
# The connection

class Truncated(ExchangeFailed):
    pass


class CleanEOF(ExchangeFailed):
    pass


class Connection:
    """One TCP connection. Never reconnects."""

    def __init__(self, host, port, timeout, trace, dump=None):
        self.trace = trace
        self.dump = dump  # (sent file, received file) or None
        self.timeout = timeout
        self.next_stream = 1
        self.closed = False
        try:
            self.sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as e:
            raise ExchangeFailed("cannot connect to %s:%d: %s" % (host, port, e))
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        trace.note("connected to %s:%d" % (host, port))

    # -- raw I/O ------------------------------------------------------------

    def send_all(self, data):
        try:
            self.sock.sendall(data)
            if self.dump:
                self.dump[0].write(data)
        except socket.timeout:
            raise ExchangeFailed("timed out writing to the server")
        except OSError as e:
            raise ExchangeFailed("write failed: %s" % e)

    def recv_exact(self, n):
        """Exactly n bytes. Raises Truncated(partial) on EOF/reset part-way, CleanEOF at 0."""
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = self.sock.recv(n - len(buf))
            except socket.timeout:
                raise ExchangeFailed("timed out after %gs waiting for the server" % self.timeout)
            except (ConnectionResetError, ConnectionAbortedError):
                chunk = b""  # a reset is treated like EOF (SPEC §9 rule 4)
            except OSError as e:
                raise ExchangeFailed("read failed: %s" % e)
            if not chunk:
                if not buf:
                    raise CleanEOF("server closed the connection")
                err = Truncated("connection ended inside a frame (%d of %d bytes)" % (len(buf), n))
                err.partial = bytes(buf)
                raise err
            buf += chunk
            if self.dump:
                self.dump[1].write(chunk)
        return bytes(buf)

    # -- frames ---------------------------------------------------------------

    def send_request(self, path, headers):
        if self.next_stream > MAX_STREAM_ID:
            raise ExchangeFailed("stream IDs exhausted on this connection")  # SPEC §5.2: no wrap
        stream_id = self.next_stream
        self.next_stream += 1
        payload = encode_request(path, headers)
        header = frame_header(len(payload), T_REQUEST, END_STREAM, stream_id)
        self.send_all(header + payload)
        self.trace.frame("-->", header, payload, describe_request(path, headers))
        return stream_id

    def read_frame(self):
        """Next KNOWN frame, as (header, type, flags, stream_id, payload).

        Follows the receiver order of SPEC §4 exactly:
        12 bytes -> length check -> unknown type skip -> payload -> stream 0 check.
        """
        while True:
            try:
                header = self.recv_exact(HEADER_LEN)
            except Truncated as e:
                self.trace.partial("<--", e.partial, "frame header")
                raise
            length = struct.unpack_from(">I", header, 0)[0]
            ftype = header[4]
            if length > MAX_PAYLOAD:
                self.trace.frame("<--", header, None, ["Length %d > %d" % (length, MAX_PAYLOAD)])
                if ftype == T_ERROR:
                    raise ExchangeFailed("server sent an oversized ERROR frame (length %d)" % length)
                raise ConnectionFault(ERR_FRAME_TOO_LARGE, "frame length %d exceeds %d" % (length, MAX_PAYLOAD))
            try:
                payload = self.recv_exact(length) if length else b""
            except CleanEOF:
                self.trace.partial("<--", b"", "payload (0 of %d)" % length)
                raise Truncated("connection ended inside a frame (0 of %d payload bytes)" % length)
            except Truncated as e:
                self.trace.partial("<--", header + e.partial, "frame")
                raise
            if ftype not in KNOWN_TYPES:
                self.trace.frame("<--", header, payload)
                continue  # SPEC §4.3: skipped, nothing else examined
            flags = header[5]
            stream_id = struct.unpack_from(">I", header, 8)[0]
            if ftype in (T_REQUEST, T_RESPONSE, T_DATA) and stream_id == 0:
                self.trace.frame("<--", header, payload)
                raise ConnectionFault(ERR_INVALID_STREAM_ID, "%s on stream 0" % KNOWN_TYPES[ftype])
            return header, ftype, flags, stream_id, payload

    # -- one exchange ---------------------------------------------------------

    def exchange(self, path, headers, sink):
        """Send one GET and stream the body into sink. Returns (status, headers, body_len)."""
        stream_id = self.send_request(path, headers)
        status = None
        resp_headers = []
        expected = []
        received = 0
        while True:
            try:
                header, ftype, flags, sid, payload = self.read_frame()
            except CleanEOF:
                raise ExchangeFailed("server closed the connection before END_STREAM on stream %d" % stream_id)

            if ftype == T_ERROR:
                self.trace.frame("<--", header, payload, describe_error(payload))
                raise PeerError("server sent ERROR: %s" % summarize_error(payload))
            if ftype == T_REQUEST:
                self.trace.frame("<--", header, payload)
                raise ConnectionFault(ERR_PROTOCOL, "REQUEST received by a client")
            if sid != stream_id:
                self.trace.frame("<--", header, payload)
                raise ExchangeFailed("%s on stream %d while waiting for stream %d"
                                     % (KNOWN_TYPES[ftype], sid, stream_id))

            if ftype == T_RESPONSE:
                if status is not None:
                    self.trace.frame("<--", header, payload)
                    raise ExchangeFailed("second RESPONSE on stream %d" % stream_id)
                try:
                    status, resp_headers = decode_response(payload)
                except ExchangeFailed:
                    self.trace.frame("<--", header, payload)
                    raise
                self.trace.frame("<--", header, payload, describe_response(status, resp_headers))
                expected = content_lengths(resp_headers)
            else:  # DATA
                self.trace.frame("<--", header, payload)
                if status is None:
                    raise ExchangeFailed("DATA before RESPONSE on stream %d" % stream_id)
                received += len(payload)
                for n in expected:
                    if received > n:
                        raise ExchangeFailed("body exceeds content-length %d" % n)
                if payload:
                    sink(payload)

            # Undefined flag bits on RESPONSE/DATA are ignored (SPEC §3).
            if flags & END_STREAM:
                for n in expected:
                    if received != n:
                        raise ExchangeFailed("content-length is %d but the body was %d bytes" % (n, received))
                self.trace.note("stream %d complete: status %d, %d body bytes" % (stream_id, status, received))
                return status, resp_headers, received

    # -- closing --------------------------------------------------------------

    def send_error_and_close(self, code, message):
        """SPEC §9.3: send ERROR, half-close, drain (bounded), then close."""
        frame = encode_error(code, message)
        try:
            self.send_all(frame)
            self.trace.frame("-->", frame[:HEADER_LEN], frame[HEADER_LEN:],
                             describe_error(frame[HEADER_LEN:]))
            self.sock.shutdown(socket.SHUT_WR)
            deadline = time.monotonic() + DRAIN_SECONDS
            drained = 0
            while drained < DRAIN_BYTES:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                self.sock.settimeout(left)
                chunk = self.sock.recv(min(4096, DRAIN_BYTES - drained))
                if not chunk:
                    break
                drained += len(chunk)
        except (OSError, ExchangeFailed):
            pass  # best effort (SPEC §9.3); a reset here is the same as EOF
        self.close()

    def close(self):
        if not self.closed:
            self.closed = True
            try:
                self.sock.close()
            except OSError:
                pass
            self.trace.note("connection closed")


def summarize_error(payload):
    if len(payload) < 4:
        return "malformed ERROR payload (%d bytes)" % len(payload)
    code, mlen = struct.unpack_from(">HH", payload, 0)
    msg = payload[4:4 + mlen].decode("utf-8", "replace")
    return "code %d %s%s" % (code, ERROR_NAMES.get(code, "(unknown code)"), ": " + msg if msg else "")


def describe_error(payload):
    return ["decoded  " + summarize_error(payload)]


# ---------------------------------------------------------------------------
# Command line

def split_target(arg):
    """'[bhttp://]host:port/path' -> (host, port, path bytes). '/path' -> (None, None, path)."""
    raw = os.fsencode(arg) if os.name != "nt" else arg.encode("utf-8", "surrogateescape")
    if raw.startswith(b"/"):
        return None, None, raw
    if raw.lower().startswith(b"bhttp://"):
        raw = raw[len(b"bhttp://"):]
    slash = raw.find(b"/")
    hostport, path = (raw, b"/") if slash < 0 else (raw[:slash], raw[slash:])
    hostport = hostport.decode("ascii", "replace")
    if hostport.startswith("["):  # [::1]:9000
        host, _, rest = hostport[1:].partition("]")
        port_text = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port_text = hostport.rpartition(":")
    if not host or not port_text.isdigit() or not 0 < int(port_text) < 65536:
        raise UsageError("target %r must look like host:port/path (BHTTP/1 has no default port)" % arg)
    return host, int(port_text), path


USAGE = """usage: bcurl [-v] [-H "name: value"]... [-o FILE] [-t SECONDS] [--dump PREFIX] HOST:PORT/PATH [/PATH | HOST:PORT/PATH]...

  -v            hexdump every frame sent and received to stderr
  -H HEADER     add a request header (repeatable); table names go out by ID
  -o FILE       write the body to FILE instead of stdout (single target only;
                the file is only created if the exchange succeeds)
  -t SECONDS    how long to wait for the server on each read (default 30)
  --dump PREFIX also write the raw bytes sent and received to PREFIX.request.bin
                and PREFIX.response.bin (see tools/annotate.py)
  -h, --help    show this help

All targets share one connection and must name the same host:port.
Exit: 0 ok, 1 a 4xx/5xx status, 2 bad usage, 3 the exchange failed."""


def parse_args(argv):
    opts = {"verbose": False, "headers": [], "output": None, "timeout": 30.0, "dump": None, "targets": []}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(USAGE)
            sys.exit(EXIT_OK)
        elif a == "-v":
            opts["verbose"] = True
        elif a in ("-H", "-o", "-t", "--dump"):
            if i + 1 >= len(argv):
                raise UsageError("%s needs an argument" % a)
            i += 1
            if a == "-H":
                opts["headers"].append(parse_header_arg(argv[i]))
            elif a == "-o":
                opts["output"] = argv[i]
            elif a == "--dump":
                opts["dump"] = argv[i]
            else:
                try:
                    opts["timeout"] = float(argv[i])
                except ValueError:
                    raise UsageError("-t needs a number of seconds")
                if opts["timeout"] <= 0:
                    raise UsageError("-t needs a positive number of seconds")
        elif a == "--":
            opts["targets"].extend(argv[i + 1:])
            break
        elif a.startswith("-") and len(a) > 1:
            raise UsageError("unknown option %s" % a)
        else:
            opts["targets"].append(a)
        i += 1
    if not opts["targets"]:
        raise UsageError("no target given")

    host = port = None
    paths = []
    for t in opts["targets"]:
        h, p, path = split_target(t)
        if h is None:
            if host is None:
                raise UsageError("the first target must include host:port")
        elif host is None:
            host, port = h, p
        elif (h, p) != (host, port):
            raise UsageError("all targets must use %s:%d: one connection only" % (host, port))
        paths.append(path)
    if opts["output"] and len(paths) > 1:
        raise UsageError("-o works with a single target")
    for path in paths:
        encode_request(path, opts["headers"])  # size checks before anything is sent
    return opts, host, port, paths


def run(argv, stdout=None, stderr=None):
    stdout = stdout if stdout is not None else sys.stdout.buffer
    stderr = stderr if stderr is not None else sys.stderr
    try:
        opts, host, port, paths = parse_args(argv)
    except UsageError as e:
        stderr.write("bcurl: %s\n%s\n" % (e, USAGE))
        return EXIT_USAGE

    trace = Trace(opts["verbose"], stderr)
    out_path = opts["output"]
    tmp_path = out_path + ".part" if out_path else None
    out = open(tmp_path, "wb") if out_path else stdout
    dump = None
    if opts["dump"]:
        dump = (open(opts["dump"] + ".request.bin", "wb"), open(opts["dump"] + ".response.bin", "wb"))
    worst = EXIT_OK
    completed = False  # anything that escapes the loop (Ctrl-C, disk full) must not publish the file
    conn = None
    try:
        conn = Connection(host, port, opts["timeout"], trace, dump)
        for path in paths:
            status, _headers, _n = conn.exchange(path, opts["headers"], out.write)
            out.flush()
            if status >= 400:
                stderr.write("bcurl: %s -> %d\n" % (show(path), status))
                worst = EXIT_HTTP_ERROR
        conn.close()
        completed = True
    except ConnectionFault as e:
        stderr.write("bcurl: protocol fault, sending ERROR and closing: %s\n" % e)
        conn.send_error_and_close(e.code, e.wire_message)
        worst = EXIT_FAILED
    except ExchangeFailed as e:
        stderr.write("bcurl: exchange failed: %s\n" % e)
        if conn:
            conn.close()
        worst = EXIT_FAILED
    finally:
        for f in dump or ():
            f.close()
        if out_path:
            out.close()
            if completed:
                os.replace(tmp_path, out_path)
            else:
                os.remove(tmp_path)
    return worst


def main():
    try:
        sys.exit(run(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(EXIT_FAILED)


if __name__ == "__main__":
    main()
