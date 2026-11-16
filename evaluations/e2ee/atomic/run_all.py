#!/usr/bin/env python3
"""Reproduce process/Git checks and the upstream native SQLite-provider check."""
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
EVAL = HERE.parent


def main():
    os.umask(0o077)
    env = os.environ.copy()
    env["CARGO_BUILD_JOBS"] = "4"
    subprocess.run(["cargo", "build", "--locked", "--manifest-path", str(EVAL / "rust/Cargo.toml"),
                    "--bin", "openmls-worker", "--bin", "sqlite-provider-probe"], env=env, check=True)
    result = subprocess.run(["python3", str(HERE / "run_experiment.py")], check=True, capture_output=True, text=True)
    report = json.loads(result.stdout)
    with tempfile.TemporaryDirectory(prefix="yhes-native-provider-") as temporary:
        root = Path(temporary)
        (root / "EXPERIMENT_ONLY").touch()
        result = subprocess.run([str(EVAL / "rust/target/debug/sqlite-provider-probe"), str(root)],
                                check=True, capture_output=True, text=True)
        report["native_provider_results"] = [json.loads(line) for line in result.stdout.splitlines() if line]
    report.update(evaluated_on="2026-11-13", platform=platform.platform(), python_sqlite_version=sqlite3.sqlite_version,
                  rust=subprocess.check_output(["rustc", "--version"], text=True).strip())
    report["all_checks_passed"] = all(all(row["checks"].values()) for row in report["results"] + report["native_provider_results"])
    files = [HERE / name for name in ("adapter.py", "git_fixture.py", "run_experiment.py", "run_all.py")]
    files += [EVAL / "rust/src/worker.rs", EVAL / "rust/src/sqlite_provider.rs", EVAL / "rust/Cargo.lock"]
    report["source_sha256"] = {str(path.relative_to(EVAL)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    (HERE / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
