#!/usr/bin/env python3
"""
Attempt to recover a corrupted Legion SQLite project file.

The script will first run PRAGMA quick_check. If the database is healthy, it will
create a consistent backup at the requested output path. If corruption is detected,
the script will try to salvage the data by dumping the schema/data (using Python's
sqlite3 iterdump and falling back to the sqlite3 CLI '.recover' command when needed)
and rebuilding a new database.
"""

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Tuple


def quick_check(path: Path) -> Tuple[bool, str]:
    """Run PRAGMA quick_check on the database and return (ok, details)."""
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
            rows = conn.execute("PRAGMA quick_check").fetchall()
    except sqlite3.DatabaseError as exc:
        return False, str(exc)

    if not rows:
        return False, "quick_check returned no rows"

    issues = [row[0] for row in rows if isinstance(row, (list, tuple)) and row and row[0].lower() != "ok"]
    if issues:
        return False, "; ".join(issues)
    return True, "ok"


def backup_sqlite(src: Path, dst: Path) -> None:
    """Use sqlite3 backup API to create a faithful copy of src at dst."""
    if dst.exists():
        dst.unlink()
    if dst.parent and not dst.parent.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(f"file:{src}?mode=ro", uri=True) as source, sqlite3.connect(str(dst)) as target:
        source.backup(target)


def dump_via_iterdump(src: Path, dump_file: Path) -> None:
    """Attempt to dump the database using Connection.iterdump()."""
    with sqlite3.connect(f"file:{src}?mode=ro", uri=True) as conn, dump_file.open("w", encoding="utf-8") as dump:
        for line in conn.iterdump():
            dump.write(f"{line}\n")


def dump_via_sqlite_cli(src: Path, dump_file: Path) -> None:
    """Fallback to sqlite3 CLI .recover output when python iterdump cannot read the DB."""
    sqlite_bin = shutil.which("sqlite3")
    if not sqlite_bin:
        raise RuntimeError("sqlite3 CLI not found in PATH; cannot run .recover fallback.")

    with dump_file.open("w", encoding="utf-8") as dump:
        proc = subprocess.run(
            [sqlite_bin, str(src), ".recover"],
            stdout=dump,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    if proc.returncode != 0:
        raise RuntimeError(f"sqlite3 .recover failed: {proc.stderr.strip()}")


def rebuild_from_dump(dump_file: Path, output: Path) -> None:
    """Create a new SQLite database by executing the dump script."""
    if output.exists():
        output.unlink()
    if output.parent and not output.parent.exists():
        output.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(output)) as conn, dump_file.open("r", encoding="utf-8") as dump:
        conn.executescript(dump.read())


def recover_database(src: Path, dst: Path) -> None:
    """Recover a corrupted SQLite database."""
    with tempfile.TemporaryDirectory(prefix="legion-repair-") as tmpdir:
        dump_path = Path(tmpdir) / "dump.sql"
        try:
            dump_via_iterdump(src, dump_path)
        except sqlite3.DatabaseError:
            dump_via_sqlite_cli(src, dump_path)

        rebuild_from_dump(dump_path, dst)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Repair or copy a Legion SQLite project file.")
    parser.add_argument("input", type=Path, help="Path to the corrupted (or healthy) .legion SQLite file.")
    parser.add_argument(
        "output", type=Path, help="Destination path for the recovered database (will be overwritten)."
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the destination file even if it already exists.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = args.input
    output_path = args.output

    if not input_path.exists():
        print(f"Input database '{input_path}' does not exist.", file=sys.stderr)
        return 1

    if output_path.exists() and not args.force:
        print(f"Output file '{output_path}' already exists. Use --force to overwrite.", file=sys.stderr)
        return 1

    print(f"[+] Running integrity check on {input_path}...")
    ok, details = quick_check(input_path)
    if ok:
        print("[+] Database appears healthy. Creating backup copy.")
        backup_sqlite(input_path, output_path)
    else:
        print(f"[!] Integrity check failed: {details}")
        print("[*] Attempting recovery via dump/restore...")
        try:
            recover_database(input_path, output_path)
        except Exception as exc:
            print(f"[x] Recovery failed: {exc}", file=sys.stderr)
            return 1

    ok, details = quick_check(output_path)
    if not ok:
        print(f"[x] Recovered database still fails integrity check: {details}", file=sys.stderr)
        return 1

    print(f"[+] Recovery complete. Repaired database saved to {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
