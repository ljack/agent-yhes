#!/usr/bin/env python3
"""Read-only local preview for the tutorial and its explicitly linked guides."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit
import argparse

ROOT = Path(__file__).resolve().parents[1]
GUIDES = {'/README.md', '/BOOTSTRAP.md', '/GETTING-STARTED.md', '/docs/TEAM-PILOT.md',
          '/docs/NEW-MEMBER-AGENT.md', '/docs/VALIDATION.md'}


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def send_head(self):
        path = unquote(urlsplit(self.path).path)
        if path == '/':
            self.send_response(302)
            self.send_header('Location', '/tutorial/')
            self.end_headers()
            return None
        allowed = path in GUIDES or path in {'/tutorial/', '/tutorial/index.html', '/tutorial/style.css', '/tutorial/model.js', '/tutorial/app.js'}
        if not allowed:
            self.send_error(404)
            return None
        return super().send_head()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=0)
    args = parser.parse_args()
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    print(f'http://127.0.0.1:{server.server_port}/tutorial/', flush=True)
    server.serve_forever()
