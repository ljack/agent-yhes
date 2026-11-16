"""Checks the publishable artifact, including project-site links and boundaries."""
from html.parser import HTMLParser
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from build_site import build, OUTPUTS


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        self.links.extend(value for key, value in attrs if key in {"src", "href"})


class SiteTests(unittest.TestCase):
    def test_pages_artifact_only_contains_site_files_and_revision_bound_guides(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "site"
            revision = "a" * 40
            metadata = build(output, revision=revision)
            self.assertEqual({p.name for p in output.iterdir()}, OUTPUTS)
            parser = Links()
            parser.feed((output / "index.html").read_text())
            guides = [p for p in parser.links if p.startswith("https:")]
            self.assertEqual(len(guides), 6)
            self.assertTrue(all(p.startswith(f"https://github.com/ljack/agent-yhes/blob/{revision}/") for p in guides))
            for link in parser.links:
                if not link.startswith(("https:", "data:", "#")):
                    self.assertFalse(link.startswith(("/", "..")), link)
                    self.assertTrue((output / link).is_file(), link)
            self.assertEqual(json.loads((output / "build.json").read_text()), metadata)
            before = {p.name: p.read_bytes() for p in output.iterdir()}
            build(output, revision=revision)
            self.assertEqual(before, {p.name: p.read_bytes() for p in output.iterdir()})

    def test_unrelated_output_and_symlinks_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "site"
            output.mkdir()
            private = output / "private.txt"
            private.write_text("keep this")
            with self.assertRaises(ValueError):
                build(output)
            self.assertEqual(private.read_text(), "keep this")
            private.unlink()
            target = Path(directory) / "original"
            target.write_text("keep this too")
            (output / "index.html").symlink_to(target)
            with self.assertRaises(ValueError):
                build(output)
            self.assertEqual(target.read_text(), "keep this too")


if __name__ == "__main__":
    unittest.main()
