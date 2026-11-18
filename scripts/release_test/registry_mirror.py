#!/usr/bin/env python3
"""Local cargo registry standing in for crates.io during a release test run.

It serves a sparse index, accepts `cargo publish` and keeps what it receives on
disk. The rest is mirrored from crates.io, read-only: index entries and crate
files are fetched from there when asked for, and a crate lists the versions of
crates.io along with the ones published here. Crates published here can then
depend on real ones while cargo only ever talks to this registry. Nothing is
sent to crates.io.

Meant to replace crates.io altogether in a cargo configuration:

    [registries.test-mirror]
    index = "sparse+http://127.0.0.1:<port>/index/"

    [source.crates-io]
    replace-with = "test-mirror"

It only listens on the loopback interface and is in no way a production
registry: one token, no users, no yank, no persistence guarantees.
"""

import argparse
import hashlib
import http.server
import json
import re
import struct
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

UPSTREAM_INDEX = "https://index.crates.io"
UPSTREAM_DOWNLOAD = "https://static.crates.io/crates/{name}/{name}-{version}.crate"
# How cargo names crates.io in the dependencies of a crate sent to another registry.
CRATES_IO_INDEX = "https://github.com/rust-lang/crates.io-index"
USER_AGENT = "tfhe-rs release test mirror (https://github.com/zama-ai/tfhe-rs)"

NAME = r"[A-Za-z0-9_-]+"
INDEX_FILE = re.compile(rf"(?:[123]|{NAME})(?:/{NAME}){{1,2}}")
DOWNLOAD = re.compile(rf"/api/v1/crates/({NAME})/([0-9A-Za-z.+-]+)/download")


def index_path(name):
    """Path of the index file of crate `name`, as laid out by cargo."""
    name = name.lower()
    if len(name) <= 2:
        return f"{len(name)}/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def index_entry(metadata, cksum):
    """Index line of a crate, from the metadata cargo sends along with it."""
    dependencies = []
    for dep in metadata["deps"]:
        renamed = dep.get("explicit_name_in_toml")
        registry = dep.get("registry")
        dependencies.append(
            {
                "name": renamed or dep["name"],
                "req": dep["version_req"],
                "features": dep["features"],
                "optional": dep["optional"],
                "default_features": dep["default_features"],
                "target": dep["target"],
                "kind": dep["kind"],
                # This registry is crates.io as far as its users can tell, and a
                # dependency on the registry holding the crate is left unnamed.
                "registry": None if registry == CRATES_IO_INDEX else registry,
                "package": dep["name"] if renamed else None,
            }
        )
    return {
        "name": metadata["name"],
        "vers": metadata["vers"],
        "deps": dependencies,
        "cksum": cksum,
        "features": metadata["features"],
        "yanked": False,
        "links": metadata.get("links"),
        "rust_version": metadata.get("rust_version"),
        "v": 2,
    }


class Mirror(http.server.ThreadingHTTPServer):
    """The registry, serving `root` on a loopback port until `stop()` is called.

    `token` is the only credential accepted by the publish endpoint.
    `upstream` mirrors crates.io for the crates that were not published here,
    except for the ones whose name starts with `local_prefix`: those only ever
    come from here, whatever crates.io ends up holding under their name.
    `index_delay` postpones the visibility of a publication in the index by that
    many seconds, the way the cache in front of a real index does.
    `rejections` maps a crate name to how many of its next publications are
    refused, to rehearse a release that fails half way.
    `events` records what happened, for the caller to check.
    """

    daemon_threads = True

    def __init__(
        self, root, token, upstream=True, local_prefix=None, index_delay=0.0, port=0
    ):
        super().__init__(("127.0.0.1", port), Handler)
        self.root = Path(root)
        self.token = token
        self.upstream = upstream
        self.local_prefix = local_prefix
        self.index_delay = index_delay
        self.rejections = {}
        self.events = []
        self.lock = threading.Lock()
        self.upstream_cache = {}
        self.url = f"http://127.0.0.1:{self.server_address[1]}"
        self.index_url = f"sparse+{self.url}/index/"
        (self.root / "index").mkdir(parents=True, exist_ok=True)
        (self.root / "crates").mkdir(parents=True, exist_ok=True)

    def start(self):
        threading.Thread(target=self.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.shutdown()
        self.server_close()

    def record(self, *event):
        with self.lock:
            self.events.append(event)

    def crate_file(self, name, version):
        return self.root / "crates" / name / f"{name}-{version}.crate"

    def mirrors(self, name):
        """Whether crate `name` is looked up on crates.io when it is not here."""
        local = self.local_prefix and name.startswith(self.local_prefix)
        return self.upstream and not local

    def index(self, name):
        """Index file of crate `name`: the versions crates.io has, then the ones
        published here. None for a crate that is in neither."""
        local = self.root / "index" / index_path(name)
        parts = []
        if self.mirrors(name):
            parts.append(self.fetch(f"{UPSTREAM_INDEX}/{index_path(name)}"))
        if local.is_file():
            parts.append(local.read_bytes())
        lines = [line for part in parts if part for line in part.splitlines()]
        return b"".join(line + b"\n" for line in lines) if lines else None

    def published(self, name):
        """Versions of `name` this registry lists, with their checksums."""
        entries = map(json.loads, (self.index(name) or b"").splitlines())
        return {entry["vers"]: entry["cksum"] for entry in entries}

    def fetch(self, url):
        """What crates.io serves at `url`, None when it has nothing there."""
        with self.lock:
            if url in self.upstream_cache:
                return self.upstream_cache[url]
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            body = urllib.request.urlopen(request, timeout=60).read()
        except urllib.error.HTTPError as error:
            if error.code not in (404, 410):
                raise
            body = None
        with self.lock:
            self.upstream_cache[url] = body
        return body

    def add_to_index(self, entry):
        with self.lock:
            index = self.root / "index" / index_path(entry["name"])
            index.parent.mkdir(parents=True, exist_ok=True)
            with index.open("a") as file:
                file.write(json.dumps(entry, separators=(",", ":")) + "\n")
        self.record("indexed", entry["name"], entry["vers"])


class Handler(http.server.BaseHTTPRequestHandler):
    # Keep-alive, which cargo relies on to fetch a whole index quickly.
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def reply(self, status, body=b"", content_type="application/json", headers=()):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def reply_json(self, status, value):
        self.reply(status, json.dumps(value).encode())

    def reply_error(self, status, detail):
        # The shape cargo expects, it prints `detail` to the user.
        self.reply_json(status, {"errors": [{"detail": detail}]})

    def do_GET(self):
        mirror = self.server
        path = self.path.partition("?")[0]
        try:
            if path == "/index/config.json":
                self.reply_json(
                    200,
                    {
                        "dl": mirror.url + "/api/v1/crates/{crate}/{version}/download",
                        "api": mirror.url,
                    },
                )
            elif path.startswith("/index/"):
                self.index(path.removeprefix("/index/"))
            elif match := DOWNLOAD.fullmatch(path):
                self.download(*match.groups())
            else:
                self.reply_error(404, f"nothing at {path}")
        except (urllib.error.URLError, OSError) as error:
            mirror.record("upstream-error", path, str(error))
            self.reply_error(502, f"could not mirror {path} from crates.io: {error}")

    def index(self, path):
        mirror = self.server
        if not INDEX_FILE.fullmatch(path):
            self.reply_error(404, f"not an index file: {path}")
            return
        name = path.rpartition("/")[2]
        body = mirror.index(name) if path == index_path(name) else None
        if body is None:
            self.reply_error(404, f"no crate at {path}")
            return
        # cargo revalidates its own copy of the index with the ETag.
        etag = '"' + hashlib.sha256(body).hexdigest() + '"'
        if self.headers.get("If-None-Match") == etag:
            self.reply(304, headers=[("ETag", etag)])
        else:
            self.reply(200, body, "text/plain", headers=[("ETag", etag)])

    def download(self, name, version):
        mirror = self.server
        local = mirror.crate_file(name, version)
        if local.is_file():
            mirror.record("downloaded", name, version)
            body = local.read_bytes()
        elif mirror.mirrors(name):
            body = mirror.fetch(UPSTREAM_DOWNLOAD.format(name=name, version=version))
        else:
            body = None
        if body is None:
            self.reply_error(404, f"no crate {name} {version}")
        else:
            self.reply(200, body, "application/gzip")

    def do_PUT(self):
        mirror = self.server
        if self.path != "/api/v1/crates/new":
            self.reply_error(404, f"nothing at {self.path}")
            return
        body = self.rfile.read(int(self.headers["Content-Length"]))
        # Layout: metadata length, JSON metadata, crate length, crate; lengths are
        # 32 bit little endian.
        (metadata_length,) = struct.unpack_from("<I", body, 0)
        metadata = json.loads(body[4 : 4 + metadata_length])
        (crate_length,) = struct.unpack_from("<I", body, 4 + metadata_length)
        crate = body[8 + metadata_length : 8 + metadata_length + crate_length]
        name, version = metadata["name"], metadata["vers"]

        if self.headers.get("Authorization") != mirror.token:
            mirror.record("refused", name, version, "bad token")
            self.reply_error(403, "this token cannot publish to the test mirror")
            return
        with mirror.lock:
            rejected = mirror.rejections.get(name, 0) > 0
            if rejected:
                mirror.rejections[name] -= 1
        if rejected:
            mirror.record("refused", name, version, "rejected")
            self.reply_error(500, f"the test mirror was told to reject {name}")
            return
        try:
            listed = mirror.published(name)
        except OSError as error:
            self.reply_error(502, f"could not ask crates.io about {name}: {error}")
            return
        if version in listed or mirror.crate_file(name, version).exists():
            mirror.record("refused", name, version, "duplicate")
            self.reply_error(400, f"crate version `{version}` is already uploaded")
            return

        destination = mirror.crate_file(name, version)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(crate)
        entry = index_entry(metadata, hashlib.sha256(crate).hexdigest())
        mirror.record("published", name, version)
        if mirror.index_delay:
            timer = threading.Timer(mirror.index_delay, mirror.add_to_index, [entry])
            # Not worth waiting for when the registry is stopped.
            timer.daemon = True
            timer.start()
        else:
            mirror.add_to_index(entry)
        self.reply_json(
            200,
            {"warnings": {"invalid_categories": [], "invalid_badges": [], "other": []}},
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "root", help="directory holding the registry, created if needed"
    )
    parser.add_argument("--port", type=int, default=0, help="defaults to a free one")
    parser.add_argument("--token", default="test-mirror-token")
    parser.add_argument(
        "--no-upstream",
        action="store_true",
        help="do not mirror crates.io, only serve what was published here",
    )
    parser.add_argument(
        "--index-delay",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="delay before a publication shows in the index",
    )
    args = parser.parse_args()

    mirror = Mirror(
        args.root,
        args.token,
        upstream=not args.no_upstream,
        index_delay=args.index_delay,
        port=args.port,
    )
    print(f"index: {mirror.index_url}", flush=True)
    print(f"token: {mirror.token}", flush=True)
    try:
        mirror.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
