"""Annotate a captured BHTTP/1 exchange byte by byte, as Markdown.

    python bcurl.py --dump capture -H "x-client: bcurl-py" localhost:9000/index.html
    python tools/annotate.py capture.request.bin capture.response.bin > annotated.md

Input is the raw bytes bcurl wrote to and read from the socket. Every byte is
accounted for: the tool fails if a frame does not decode or bytes are left over.
"""

import struct
import sys

TYPES = {1: "REQUEST", 2: "RESPONSE", 3: "DATA", 4: "ERROR"}
HEADERS = {1: "content-type", 2: "content-length", 3: "server", 4: "date", 5: "connection",
           6: "content-encoding", 7: "cache-control", 8: "last-modified"}
ERRORS = {1: "FRAME_TOO_LARGE", 2: "INVALID_STREAM_ID", 3: "PROTOCOL_ERROR"}
BODY_PREVIEW = 32


def hx(b):
    return " ".join("%02X" % x for x in b)


def text(b):
    s = b.decode("utf-8", "backslashreplace")
    return "`" + s.replace("`", "\\`").replace("\n", "\\n").replace("\r", "\\r") + "`"


class Annotator:
    def __init__(self, data, base):
        self.data = data
        self.base = base  # offset of the payload within the stream, for the table
        self.pos = 0
        self.rows = []

    def take(self, n, field, meaning):
        if self.pos + n > len(self.data):
            raise SystemExit("decode error: %s runs past the end (%d of %d bytes)" % (field, self.pos, len(self.data)))
        b = self.data[self.pos:self.pos + n]
        self.rows.append((self.base + self.pos, b, field, meaning))
        self.pos += n
        return b

    def u8(self, field, meaning=lambda v: str(v)):
        v = self.take(1, field, None)[0]
        self.rows[-1] = self.rows[-1][:3] + (meaning(v),)
        return v

    def u16(self, field, meaning=lambda v: str(v)):
        v = struct.unpack(">H", self.take(2, field, None))[0]
        self.rows[-1] = self.rows[-1][:3] + (meaning(v),)
        return v

    def headers(self, count):
        for i in range(1, count + 1):
            hid = self.u8("header %d: ID" % i,
                          lambda v: "0 = custom header, name follows" if v == 0 else
                          "%d = `%s` (from the table, no name on the wire)" % (v, HEADERS.get(v, "unknown, ignored")))
            if hid == 0:
                n = self.u16("header %d: name length" % i, lambda v: "%d bytes" % v)
                name = self.take(n, "header %d: name" % i, None)
                self.rows[-1] = self.rows[-1][:3] + (text(name),)
            n = self.u16("header %d: value length" % i, lambda v: "%d bytes" % v)
            value = self.take(n, "header %d: value" % i, None)
            self.rows[-1] = self.rows[-1][:3] + (text(value) if n else "(empty)",)

    def rest_must_be_empty(self):
        if self.pos != len(self.data):
            raise SystemExit("decode error: %d bytes after the last field" % (len(self.data) - self.pos))


def table(rows, collapse_body=False):
    out = ["| Offset | Bytes | Field | Meaning |", "|---:|---|---|---|"]
    for off, b, field, meaning in rows:
        shown = hx(b)
        if collapse_body and len(b) > BODY_PREVIEW:
            shown = hx(b[:BODY_PREVIEW]) + " … (%d more)" % (len(b) - BODY_PREVIEW)
        out.append("| %d | `%s` | %s | %s |" % (off, shown, field, meaning))
    return "\n".join(out)


def annotate_stream(data, direction):
    out = []
    pos = n = 0
    while pos < len(data):
        n += 1
        if pos + 12 > len(data):
            raise SystemExit("decode error: truncated frame header at %d" % pos)
        length, ftype, flags, reserved, sid = struct.unpack(">IBBHI", data[pos:pos + 12])
        name = TYPES.get(ftype, "unknown type %d" % ftype)
        out.append("### %s frame %d: %s, stream %d, %d payload bytes\n" % (direction, n, name, sid, length))
        out.append("Frame header (12 bytes, stream offset %d):\n" % pos)
        h = Annotator(data[pos:pos + 12], pos)
        h.take(4, "Length (u32)", "%d payload bytes follow the header" % length)
        h.take(1, "Type (u8)", "0x%02X = %s" % (ftype, name))
        fl = "END_STREAM: last frame of this stream" if flags == 1 else ("none" if flags == 0 else "0x%02X" % flags)
        h.take(1, "Flags (u8)", fl)
        h.take(2, "Reserved (u16)", "always 0 from the sender, ignored by the receiver" if reserved == 0 else str(reserved))
        h.take(4, "Stream ID (u32)", "stream %d" % sid if sid else "0 = connection level")
        out.append(table(h.rows) + "\n")

        payload = data[pos + 12:pos + 12 + length]
        if len(payload) != length:
            raise SystemExit("decode error: frame %d payload truncated" % n)
        p = Annotator(payload, pos + 12)
        if ftype == 1:
            p.u8("Method (u8)", lambda v: "0x%02X = GET" % v if v == 1 else "0x%02X (undefined)" % v)
            plen = p.u16("Path Length (u16)", lambda v: "%d bytes" % v)
            path = p.take(plen, "Path", None)
            p.rows[-1] = p.rows[-1][:3] + (text(path) + ", raw UTF-8, no terminator",)
            p.headers(p.u8("Header Count (u8)", lambda v: "%d header(s)" % v))
        elif ftype == 2:
            p.u16("Status (u16)", lambda v: "%d" % v)
            p.headers(p.u8("Header Count (u8)", lambda v: "%d header(s)" % v))
        elif ftype == 3:
            if length:
                p.take(length, "Body bytes", "%d bytes of the file, unmodified" % length)
        elif ftype == 4:
            p.u16("Code (u16)", lambda v: "%d = %s" % (v, ERRORS.get(v, "unknown")))
            m = p.u16("Msg Len (u16)", lambda v: "%d bytes" % v)
            msg = p.take(m, "Msg", None)
            p.rows[-1] = p.rows[-1][:3] + (text(msg),)
        else:
            if length:
                p.take(length, "Payload", "unknown type: skipped by length, never parsed")
        p.rest_must_be_empty()
        if p.rows:
            out.append("Payload (%d bytes, stream offset %d):\n" % (length, pos + 12))
            out.append(table(p.rows, collapse_body=(ftype == 3)) + "\n")
        pos += 12 + length
    return "\n".join(out), n


def raw_dump(data):
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        h = hx(chunk[:8]) + ("  " + hx(chunk[8:]) if len(chunk) > 8 else "")
        lines.append("%08X  %-49s |%s|" % (off, h, "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)))
    return "\n".join(lines)


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    with open(sys.argv[1], "rb") as f:
        req = f.read()
    with open(sys.argv[2], "rb") as f:
        resp = f.read()
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    req_md, nreq = annotate_stream(req, "client →")
    resp_md, nresp = annotate_stream(resp, "server →")
    print("## Raw bytes\n")
    print("Client to server, %d bytes (%d frame):\n\n```text\n%s\n```\n" % (len(req), nreq, raw_dump(req)))
    print("Server to client, %d bytes (%d frames):\n\n```text\n%s\n```\n" % (len(resp), nresp, raw_dump(resp)))
    print("## Client → server\n")
    print(req_md)
    print("## Server → client\n")
    print(resp_md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
