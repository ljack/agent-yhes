#!/usr/bin/env python3
"""Package the static tutorial for GitHub Pages; no runtime data is copied."""
import argparse
from html import escape
import json
import os
from pathlib import Path
import re
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ("index.html", "style.css", "model.js", "app.js")
OUTPUTS = {*ASSETS, ".nojekyll", "build.json"}
GUIDES = {
    "README.md", "BOOTSTRAP.md", "GETTING-STARTED.md",
    "docs/TEAM-PILOT.md", "docs/NEW-MEMBER-AGENT.md", "docs/VALIDATION.md",
}


def resolve_guide_url(raw, repository="ljack/agent-yhes", revision="main"):
    """Validate an allowlisted repository guide path and optional anchor fragment."""
    path, sep, fragment = raw.partition("#")
    if path not in GUIDES or not (ROOT / path).is_file():
        raise ValueError(f"unknown or missing guide: {path}")
    if sep and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", fragment):
        raise ValueError(f"invalid guide fragment: {fragment}")
    suffix = f"#{fragment}" if sep else ""
    return f"https://github.com/{repository}/blob/{quote(revision, safe='')}/{path}{suffix}"


def build(output, repository="ljack/agent-yhes", revision="main"):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("repository must be owner/name")
    if not revision or re.search(r"[\s?#]", revision):
        raise ValueError("revision must be a Git ref or commit")
    output = Path(output)
    if output.is_symlink():
        raise ValueError("output must not be a symlink")
    output.mkdir(parents=True, exist_ok=True)
    if any(p.name not in OUTPUTS or not p.is_file() or p.is_symlink() for p in output.iterdir()):
        raise ValueError("output contains files outside the site artifact")
    source = ROOT / "tutorial"
    for name in ASSETS:
        if (source / name).is_symlink() or not (source / name).is_file():
            raise ValueError(f"missing or linked tutorial asset: {name}")
    html = (source / "index.html").read_text()

    def guide(match):
        return f'href="{escape(resolve_guide_url(match[1], repository, revision), quote=True)}"'

    html = re.sub(r'href="\.\./([^"]+)"', guide, html)
    if 'href="../' in html or 'src="../' in html:
        raise ValueError("site contains an unresolved parent-relative link")
    (output / "index.html").write_text(html)
    for name in ASSETS[1:]:
        (output / name).write_bytes((source / name).read_bytes())
    (output / ".nojekyll").write_text("")
    metadata = {"version": (ROOT / "VERSION").read_text().strip(),
                "repository": repository, "revision": revision}
    (output / "build.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/site")
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "ljack/agent-yhes"))
    parser.add_argument("--ref", dest="revision", default=os.environ.get("GITHUB_SHA", "main"))
    args = parser.parse_args()
    print(json.dumps(build(args.output, args.repository, args.revision), indent=2))
    print(f"Built {args.output}")
