"""Run the INTEROP_GUIDE §3 client checklist against a live BHTTP/1 server.

Drives the real bcurl executable (subprocess, raw stdout) so exit codes and
binary output are tested exactly as a user sees them.

    python tests/interop_check.py HOST:PORT [--docker CONTAINER]

HOST:PORT must serve the shared conformance fixture (conformance/www).
With --docker, the server container's log is read before and after the run,
and must show exactly one new "connected" line per bcurl invocation
(no reconnects, no second connection).
"""

import hashlib
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BCURL = [sys.executable, os.path.join(HERE, "..", "bcurl.py")]

# Published fixture: conformance/SHA256SUMS and INTEROP_GUIDE §2.
FIXTURE = {
    "/index.html": (115, 1, "text/html", "ee87c48e6428ffe1cf86382015d57f19526e48311f4740157e05669a86465a32"),
    "/docs/index.html": (97, 1, "text/html", "facb3ebf8bc5aa3084a9f6513f704e81677e1e7e693e40f5f9756972fd46f3c5"),
    "/assets/site.css": (54, 1, "text/css", "3432bc6516006ebeac80530d4c91f0053b7b89ce779cb46c70f3efc1dfc02354"),
    "/unicode/naïve.txt": (11, 1, "text/plain", "ebae8c0444b0cbae7ae2d1478c24c7d4975275967e8c6a8e384f482b3e437453"),
    "/binary.bin": (261, 1, "application/octet-stream", "adfed3eaaf79a08a1b57f8c6cc29901800a11ecefbadaa60a4e01d31d01fb756"),
    "/pixel.png": (69, 1, "image/png", "6f6ed35bb70f4a7e2bad7c32889826eb7199e27f70b6f398f514d4535c21a90b"),
    "/empty.txt": (0, 0, "text/plain", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    "/edge-16383.bin": (16383, 1, "application/octet-stream", "3b2cb465b73a95901a4b86bc2b135243d3c51c2c2840bb0e9e04e300fe32397f"),
    "/edge-16384.bin": (16384, 1, "application/octet-stream", "90b834666bd99804aad5f0d312a8862f91872e635fd6063d42fe787c4e1d84ee"),
    "/edge-16385.bin": (16385, 2, "application/octet-stream", "b6f80d243c7df4a24b21033a7081459a4bec6bd0d90332ed204e922f4be60145"),
    "/edge-65536.bin": (65536, 4, "application/octet-stream", "93d1a595bb5828c088e99c53df8dca5511567b7724bc2325cf3e54d725fa069b"),
}
ALIASES = {"/": "/index.html", "/docs": "/docs/index.html", "/docs/": "/docs/index.html"}

FRAME_RE = re.compile(r"^(-->|<--) frame \d+  (\S+)  stream=(\d+)  flags=(\S+)  length=(\d+)$", re.M)
HEADER_RE = re.compile(r"^\s+\[id (\d+)\] ([^:]+): (.*)$", re.M)


class Checker:
    def __init__(self, target):
        self.target = target
        self.passed = 0
        self.failed = 0
        self.invocations = 0

    def bcurl(self, *paths, verbose=True):
        self.invocations += 1
        args = BCURL + (["-v"] if verbose else []) + [self.target + paths[0]] + list(paths[1:])
        p = subprocess.run(args, capture_output=True, timeout=60)
        return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace").replace("\r\n", "\n")

    def check(self, item, name, cond, detail=""):
        if cond:
            self.passed += 1
            print("PASS  %-4s %s" % (item, name))
        else:
            self.failed += 1
            print("FAIL  %-4s %s  %s" % (item, name, detail))


def frames(err):
    return [(d, t, int(s), f, int(n)) for d, t, s, f, n in FRAME_RE.findall(err)]


def body_check(c, item, path, real):
    size, nframes, ctype, digest = FIXTURE[real]
    code, out, err = c.bcurl(path)
    fs = [f for f in frames(err) if f[0] == "<--"]
    resp = [f for f in fs if f[1] == "RESPONSE"]
    data = [f for f in fs if f[1] == "DATA"]
    hdrs = HEADER_RE.findall(err)
    c.check(item, "GET %s exit 0" % path, code == 0, "exit=%d %s" % (code, err[-300:]))
    c.check(item, "GET %s %d bytes, sha256" % (path, size),
            len(out) == size and hashlib.sha256(out).hexdigest() == digest, "got %d bytes" % len(out))
    c.check(item, "GET %s headers" % path,
            ("1", "content-type", ctype) in hdrs and ("2", "content-length", str(size)) in hdrs, hdrs)
    c.check(item, "GET %s %d DATA frame(s)" % (path, nframes), len(data) == nframes, data)
    if nframes:
        sizes = [f[4] for f in data]
        want = [16384] * (size // 16384) + ([size % 16384] if size % 16384 else [])
        c.check(item, "GET %s frame sizes %s, END_STREAM last only" % (path, want),
                sizes == want and all(("END_STREAM" in f[3]) == (i == len(data) - 1) for i, f in enumerate(data)),
                data)
    else:
        c.check(item, "GET %s END_STREAM on RESPONSE, no DATA" % path,
                len(resp) == 1 and "END_STREAM" in resp[0][3] and not data, fs)


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    argv = sys.argv[1:]
    container = None
    if "--docker" in argv:
        i = argv.index("--docker")
        container = argv[i + 1]
        del argv[i:i + 2]
    if len(argv) != 1:
        print(__doc__)
        return 2
    c = Checker(argv[0].rstrip("/"))
    conns_before = server_connections(container) if container else 0

    print("== Bodies and framing")
    code, a, _ = c.bcurl("/", verbose=False)
    code2, b, _ = c.bcurl("/index.html", verbose=False)
    c.check("1", "GET / and GET /index.html identical", code == code2 == 0 and a == b and len(a) == 115)
    for item, path in [("1", "/"), ("1", "/index.html"), ("2", "/docs"), ("2", "/docs/"),
                       ("3", "/assets/site.css"), ("4", "/unicode/naïve.txt"), ("5", "/binary.bin"),
                       ("-", "/pixel.png"), ("6", "/edge-16383.bin"), ("7", "/edge-16384.bin"),
                       ("8", "/edge-16385.bin"), ("9", "/edge-65536.bin"), ("10", "/empty.txt")]:
        body_check(c, item, path, ALIASES.get(path, path))

    print("== Errors")
    code, out, err = c.bcurl("/nope")
    resp = [f for f in frames(err) if f[1] == "RESPONSE"]
    c.check("11", "GET /nope -> 404, exit 1, empty body, END_STREAM on RESPONSE",
            code == 1 and "-> 404" in err and out == b"" and resp and "END_STREAM" in resp[0][3]
            and ("2", "content-length", "0") in HEADER_RE.findall(err), err[-300:])
    for bad in ["/a:b", "/../x", "/a\\b", "//x", "/con", "/index.html."]:
        code, out, err = c.bcurl(bad)
        c.check("12", "GET %s -> 400, exit 1" % bad, code == 1 and "-> 400" in err and out == b"", err[-200:])

    print("== Connection behaviour")
    seq = ["/nope", "/a:b", "/index.html", "/../x", "/empty.txt", "/binary.bin"]
    code, out, err = c.bcurl(*seq)
    sent = [f[2] for f in frames(err) if f[0] == "-->" and f[1] == "REQUEST"]
    c.check("13", "requests after 400/404 work on the same connection",
            code == 1 and sent == list(range(1, len(seq) + 1)) and
            bodies_match(["/index.html", "/empty.txt", "/binary.bin"], out), err[-300:])
    c.check("14", "exit status non-zero after 404 and 400", code == 1)

    ten = ["/index.html", "/docs", "/assets/site.css", "/unicode/naïve.txt", "/binary.bin",
           "/pixel.png", "/empty.txt", "/edge-16384.bin", "/edge-16385.bin", "/edge-65536.bin"]
    code, out, err = c.bcurl(*ten)
    sent = [f[2] for f in frames(err) if f[0] == "-->" and f[1] == "REQUEST"]
    c.check("15", "ten requests: stream IDs 1..10 on the wire", code == 0 and sent == list(range(1, 11)), sent)
    c.check("15", "ten requests: every body intact, in order", bodies_match(ten, out))
    # The server keeps an idle connection open for 30 s, so a client that waits
    # for the close instead of stopping at END_STREAM takes that long.
    started = time.monotonic()
    code, _, err = c.bcurl("/index.html")
    elapsed = time.monotonic() - started
    c.check("16", "client stops after last END_STREAM (does not wait for close)",
            code == 0 and elapsed < 10 and "server closed" not in err, "took %.1fs" % elapsed)

    if container:
        conns = server_connections(container) - conns_before
        c.check("15", "server log: one connection per bcurl run (%d runs)" % c.invocations,
                conns == c.invocations, "new connected lines=%d" % conns)

    print("== %d passed, %d failed" % (c.passed, c.failed))
    return 1 if c.failed else 0


def server_connections(container):
    log = subprocess.run(["docker", "logs", container], capture_output=True, text=True,
                         encoding="utf-8", errors="replace")
    return len(re.findall(r" connected$", log.stdout + log.stderr, re.M))


def bodies_match(paths, out):
    """Split concatenated stdout by fixture sizes; every piece must hash right, nothing left over."""
    pos = 0
    for p in paths:
        size, _, _, digest = FIXTURE[ALIASES.get(p, p)]
        if hashlib.sha256(out[pos:pos + size]).hexdigest() != digest:
            return False
        pos += size
    return pos == len(out)


if __name__ == "__main__":
    sys.exit(main())
