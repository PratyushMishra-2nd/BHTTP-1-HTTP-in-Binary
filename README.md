# bcurl — a BHTTP/1 client (Track 2)

```bash
./bcurl -v localhost:9000/index.html
```

`bcurl` builds the binary request frame, reads the response, writes the body to
stdout, hexdumps every frame with `-v`, exits non-zero on 4xx/5xx, and never
opens a second connection.

It is written in Python (standard library only) from the BHTTP/1 specification
alone — `protocol/SPEC.md`, `WIRE_FORMAT.md` and `HEADER_TABLE.md` in
[Ujjwaljain16/BHTTP-1-HTTP-in-Binary](https://github.com/Ujjwaljain16/BHTTP-1-HTTP-in-Binary).
The server it is tested against, `bserve`, is written in Go. The two share no
code: the only thing that crosses between them is the spec.

## Usage

```text
bcurl [-v] [-H "name: value"]... [-o FILE] [-t SECONDS] [--dump PREFIX] HOST:PORT/PATH [/PATH ...]
```

| Option | Meaning |
|---|---|
| `-v` | Hexdump every frame sent and received to stderr, from the exact bytes on the socket, with decoded fields |
| `-H "name: value"` | Add a request header. Table names (`content-type`, …) go out by ID; others as lowercase custom headers |
| `-o FILE` | Write the body to FILE. The file only appears if the exchange completes (including a 4xx/5xx answer, whose body may be empty), so a truncated or interrupted download never looks complete |
| `-t SECONDS` | How long to wait on each read (default 30). Per read, not a total deadline: a server trickling bytes can keep the download going |
| `--dump PREFIX` | Also save raw bytes to `PREFIX.request.bin` / `PREFIX.response.bin` (for `tools/annotate.py`) |

Several paths on one command line are fetched **in order over one connection**,
with stream IDs 1, 2, 3, …:

```bash
./bcurl localhost:9000/index.html /docs /nope /binary.bin > out.bin
```

| Exit | Meaning |
|---|---|
| 0 | every response was 100–399 |
| 1 | at least one 4xx/5xx (the connection stays usable and later requests are still sent) |
| 2 | bad usage; nothing was sent |
| 3 | the exchange failed: refused connection, ERROR frame, EOF/truncation, or a response that breaks the protocol |

On Windows use `bcurl.cmd` (or `python bcurl.py`). Python 3.7+.

## How it follows the spec

- **Exact reads.** 12 header bytes, then exactly `Length` payload bytes, in a
  loop. One `recv` is never assumed to be one frame (`SPEC §2.3`).
- **Receiver order, §4.** Length is checked against 16384 *before* reading the
  payload; then unknown types are skipped by length without looking at Flags,
  Reserved or Stream ID; then stream 0 is checked; only then the payload is parsed.
- **Faults.** Oversize frame → `ERROR(1)`; RESPONSE/DATA on stream 0 → `ERROR(2)`;
  a REQUEST arriving at the client → `ERROR(3)`. After sending an ERROR the client
  half-closes, drains for at most 1 s / 64 KiB, then closes (`§9.3`). A received
  ERROR is never answered.
- **Response rules, §12.** RESPONSE must come first and only once, every frame
  must carry the current stream ID, status must be 100–599, headers parse
  structurally (unknown IDs 9–255 ignored), no bytes may follow the last header,
  and every `content-length` must be 1–19 digits equal to the DATA total.
  Undefined flag bits on RESPONSE/DATA are ignored. Empty DATA frames are tolerated.
- **END_STREAM ends the response.** An empty body ends on the RESPONSE frame; the
  client stops reading there and never waits for the connection to close.
- **One connection.** Stream IDs 1, 2, 3, …; after a protocol failure the client
  closes and does not reconnect; remaining paths are not sent.
- **Paths go on the wire as typed:** UTF-8, no percent-encoding, no
  normalisation. `/a:b`, `/../x`, `//x` are sent unmodified so the server can
  answer `400`.

## Tests and results

Unit tests run `bcurl` against a scripted fake server that replays exact bytes,
covering what a correct server never sends: oversized frames, stream 0, ERROR
frames, truncation, noise frames with garbage flags/stream IDs, one-byte
delivery, wrong stream IDs, bad `content-length`, trailing bytes.

```bash
python -m unittest discover -s tests -v          # 42 tests
```

The interop runner works through the client checklist in the server repo's
`docs/INTEROP_GUIDE.md` §3 (items 1–17) against a live server, running the real
executable and checking exit codes, SHA-256 of every body, DATA frame sizes,
END_STREAM placement, stream IDs on the wire and the server's own log.

```bash
# server (from the server repo): docker build -t bhttp . && docker run -d --name bserve -p 9000:9000 bhttp
python tests/interop_check.py localhost:9000 --docker bserve
```

Run against `bserve` (Go, Docker image built from the server repo):

| Path | Result | Log |
|---|---|---|
| bcurl → bserve | 79 / 79 pass | `tests/logs/bcurl-vs-bserve.txt` |
| bcurl → bchaos `-chunk 1` → bserve | 78 / 78 pass | `tests/logs/bcurl-vs-bchaos_chunk1.txt` |
| bcurl → bchaos `-chunk 7 -delay 1ms` → bserve | 78 / 78 pass | `tests/logs/bcurl-vs-bchaos_chunk7_delay1ms.txt` |
| bcurl → bchaos `-noise` → bserve | 78 / 78 pass | `tests/logs/bcurl-vs-bchaos_noise.txt` |
| bcurl → bchaos `-chunk 5 -noise -seed 42` → bserve | 78 / 78 pass | `tests/logs/bcurl-vs-bchaos_chunk5_noise_seed42.txt` |

(The direct run has one extra check: the server log shows exactly one connection
per `bcurl` invocation, 24 of 24.) `bchaos` runs from the same image:

```bash
MSYS_NO_PATHCONV=1 docker run -d --name bchaos -p 9100:9100 --entrypoint /bchaos bhttp \
    -target host.docker.internal:9000 -listen 0.0.0.0:9100 -chunk 1
python tests/interop_check.py localhost:9100
```

The request bytes for `GET /index.html` are byte-for-byte identical to the
reference capture in `INTEROP_GUIDE.md` §5, and so are the decoded responses for
`/index.html`, `/empty.txt` and `/nope`.

## Hand-in

1. **The spec** — shared with the server track: `protocol/` in the server repo.
2. **The program** — `bcurl.py` (launchers `bcurl`, `bcurl.cmd`).
3. **Annotated hexdump** — [`docs/ANNOTATED_HEXDUMP.md`](docs/ANNOTATED_HEXDUMP.md):
   one complete request and response, every byte labelled, generated from a real
   capture (`docs/capture/`) by `tools/annotate.py`.

## Notes on the spec from the client side

Places where the text needed a decision while writing the client:

- **Bytes after the last header in a RESPONSE.** `SPEC §12.7` lists only a bad
  name length or a header running past the payload as malformed for a client;
  `WIRE_FORMAT §6` says the payload MUST end exactly after the last header.
  This client follows `WIRE_FORMAT` and rejects trailing bytes. §12.7 could say so.
- **`content-length` exceeded mid-stream.** §12.5 checks it "at END_STREAM";
  this client fails as soon as the DATA total passes it, which is the same
  verdict, earlier, and keeps a hostile server from streaming forever.
- **Unknown frames after the final END_STREAM** (as `bchaos -noise` sends) are
  left unread when the client closes. That is allowed — the stream is complete —
  but it means the close can surface as a reset on the server side.
- **No path syntax for a missing leading slash.** `host:port/path` always yields
  a path starting with `/`, so this client cannot send `index.html`; the
  INTEROP_GUIDE permits refusing it locally.

## Files

```text
bcurl.py                 the client
bcurl, bcurl.cmd         launchers (POSIX shell, Windows)
tests/test_bcurl.py      unit tests against a scripted fake server
tests/interop_check.py   INTEROP_GUIDE §3 checklist against a live server
tests/logs/              results of the runs above
tools/annotate.py        raw capture -> byte-by-byte Markdown annotation
docs/ANNOTATED_HEXDUMP.md, docs/capture/
```
