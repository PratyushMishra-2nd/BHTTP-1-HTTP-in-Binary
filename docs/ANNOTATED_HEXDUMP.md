# Annotated hexdump: one complete exchange

One real request and response between **this client** (`bcurl.py`, Python) and
**`bserve`** (the Go reference server from
[Ujjwaljain16/BHTTP-1-HTTP-in-Binary](https://github.com/Ujjwaljain16/BHTTP-1-HTTP-in-Binary)),
serving the shared `conformance/www` fixture. The two programs share no code;
only the specification crosses between them.

Captured with:

```bash
python bcurl.py -v --dump docs/capture/index -H "x-client: bcurl-py" localhost:9000/index.html
python tools/annotate.py docs/capture/index.request.bin docs/capture/index.response.bin
```

`--dump` writes the exact bytes the client wrote to and read from the socket
(`docs/capture/index.request.bin`, `index.response.bin`); the tables below are
generated from those files, and the generator refuses to finish if any byte is
left unexplained. The client's own `-v` output for the same run is in
`docs/capture/index.verbose.txt`.

Result: status 200, exit code 0, 115 body bytes, SHA-256 `ee87c48e6428ffe1cf86382015d57f19526e48311f4740157e05669a86465a32`
(equal to `www/index.html` in the fixture's `SHA256SUMS`).

**What to notice**

- Every frame starts with the same 12-byte header: Length u32, Type u8, Flags u8,
  Reserved u16, Stream ID u32, all big-endian.
- The request carries `END_STREAM` (flags `01`) because v1 requests have no body.
- The custom header `x-client` travels with its name (ID `00`); the server's
  `content-type`, `content-length` and `server` travel as table IDs `01 02 03`
  with no name bytes at all. That is the whole header-compression scheme.
- The RESPONSE has flags `00`: a body follows. The single DATA frame carries
  `END_STREAM`, which is where the client stops reading. It does not wait for the
  connection to close; the connection stays open for the next request.
- `content-length: 115` (ASCII `31 31 35`) equals the DATA total, which the client checks.

## Raw bytes

Client to server, 48 bytes (1 frame):

```text
00000000  00 00 00 24 01 01 00 00  00 00 00 01 01 00 0B 2F  |...$.........../|
00000010  69 6E 64 65 78 2E 68 74  6D 6C 01 00 00 08 78 2D  |index.html....x-|
00000020  63 6C 69 65 6E 74 00 08  62 63 75 72 6C 2D 70 79  |client..bcurl-py|
```

Server to client, 171 bytes (2 frames):

```text
00000000  00 00 00 20 02 00 00 00  00 00 00 01 00 C8 03 01  |... ............|
00000010  00 09 74 65 78 74 2F 68  74 6D 6C 02 00 03 31 31  |..text/html...11|
00000020  35 03 00 08 62 73 65 72  76 65 2F 31 00 00 00 73  |5...bserve/1...s|
00000030  03 01 00 00 00 00 00 01  3C 21 64 6F 63 74 79 70  |........<!doctyp|
00000040  65 20 68 74 6D 6C 3E 0A  3C 74 69 74 6C 65 3E 42  |e html>.<title>B|
00000050  48 54 54 50 2F 31 20 63  6F 6E 66 6F 72 6D 61 6E  |HTTP/1 conforman|
00000060  63 65 20 73 65 72 76 65  72 3C 2F 74 69 74 6C 65  |ce server</title|
00000070  3E 0A 3C 68 31 3E 49 74  20 77 6F 72 6B 73 2E 3C  |>.<h1>It works.<|
00000080  2F 68 31 3E 0A 3C 70 3E  53 65 72 76 65 64 20 6F  |/h1>.<p>Served o|
00000090  76 65 72 20 61 20 62 69  6E 61 72 79 20 70 72 6F  |ver a binary pro|
000000A0  74 6F 63 6F 6C 2E 3C 2F  70 3E 0A                 |tocol.</p>.|
```

## Client → server

### client → frame 1: REQUEST, stream 1, 36 payload bytes

Frame header (12 bytes, stream offset 0):

| Offset | Bytes | Field | Meaning |
|---:|---|---|---|
| 0 | `00 00 00 24` | Length (u32) | 36 payload bytes follow the header |
| 4 | `01` | Type (u8) | 0x01 = REQUEST |
| 5 | `01` | Flags (u8) | END_STREAM: last frame of this stream |
| 6 | `00 00` | Reserved (u16) | always 0 from the sender, ignored by the receiver |
| 8 | `00 00 00 01` | Stream ID (u32) | stream 1 |

Payload (36 bytes, stream offset 12):

| Offset | Bytes | Field | Meaning |
|---:|---|---|---|
| 12 | `01` | Method (u8) | 0x01 = GET |
| 13 | `00 0B` | Path Length (u16) | 11 bytes |
| 15 | `2F 69 6E 64 65 78 2E 68 74 6D 6C` | Path | `/index.html`, raw UTF-8, no terminator |
| 26 | `01` | Header Count (u8) | 1 header(s) |
| 27 | `00` | header 1: ID | 0 = custom header, name follows |
| 28 | `00 08` | header 1: name length | 8 bytes |
| 30 | `78 2D 63 6C 69 65 6E 74` | header 1: name | `x-client` |
| 38 | `00 08` | header 1: value length | 8 bytes |
| 40 | `62 63 75 72 6C 2D 70 79` | header 1: value | `bcurl-py` |

## Server → client

### server → frame 1: RESPONSE, stream 1, 32 payload bytes

Frame header (12 bytes, stream offset 0):

| Offset | Bytes | Field | Meaning |
|---:|---|---|---|
| 0 | `00 00 00 20` | Length (u32) | 32 payload bytes follow the header |
| 4 | `02` | Type (u8) | 0x02 = RESPONSE |
| 5 | `00` | Flags (u8) | none |
| 6 | `00 00` | Reserved (u16) | always 0 from the sender, ignored by the receiver |
| 8 | `00 00 00 01` | Stream ID (u32) | stream 1 |

Payload (32 bytes, stream offset 12):

| Offset | Bytes | Field | Meaning |
|---:|---|---|---|
| 12 | `00 C8` | Status (u16) | 200 |
| 14 | `03` | Header Count (u8) | 3 header(s) |
| 15 | `01` | header 1: ID | 1 = `content-type` (from the table, no name on the wire) |
| 16 | `00 09` | header 1: value length | 9 bytes |
| 18 | `74 65 78 74 2F 68 74 6D 6C` | header 1: value | `text/html` |
| 27 | `02` | header 2: ID | 2 = `content-length` (from the table, no name on the wire) |
| 28 | `00 03` | header 2: value length | 3 bytes |
| 30 | `31 31 35` | header 2: value | `115` |
| 33 | `03` | header 3: ID | 3 = `server` (from the table, no name on the wire) |
| 34 | `00 08` | header 3: value length | 8 bytes |
| 36 | `62 73 65 72 76 65 2F 31` | header 3: value | `bserve/1` |

### server → frame 2: DATA, stream 1, 115 payload bytes

Frame header (12 bytes, stream offset 44):

| Offset | Bytes | Field | Meaning |
|---:|---|---|---|
| 44 | `00 00 00 73` | Length (u32) | 115 payload bytes follow the header |
| 48 | `03` | Type (u8) | 0x03 = DATA |
| 49 | `01` | Flags (u8) | END_STREAM: last frame of this stream |
| 50 | `00 00` | Reserved (u16) | always 0 from the sender, ignored by the receiver |
| 52 | `00 00 00 01` | Stream ID (u32) | stream 1 |

Payload (115 bytes, stream offset 56):

| Offset | Bytes | Field | Meaning |
|---:|---|---|---|
| 56 | `3C 21 64 6F 63 74 79 70 65 20 68 74 6D 6C 3E 0A 3C 74 69 74 6C 65 3E 42 48 54 54 50 2F 31 20 63 … (83 more)` | Body bytes | 115 bytes of the file, unmodified |

