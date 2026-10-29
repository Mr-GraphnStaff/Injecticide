"""Offline skill/package inspection: python -m skill_sandbox.scan_cli PATH.

Uses the same implementation as web/MCP scans. No model, package code,
dependency installer or network destination is invoked by this command.
Administrator-configured local signature verifiers retain their existing scope.
"""
from __future__ import annotations

import argparse
import json
import tarfile
import zipfile
from pathlib import Path

from .app import MAX_UPLOAD_BYTES, scan_upload
from .package_formats import RUNTIMES
from .governance import SOURCE_CHANNELS


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--target-runtime", choices=RUNTIMES, default="auto")
    parser.add_argument("--source-channel", choices=sorted(SOURCE_CHANNELS), default="uploaded_artifact",
                        help="Operator-supplied policy scenario; does not authenticate runtime provenance")
    parser.add_argument("--output", type=Path, help="Write a JSON report instead of stdout; refuses to overwrite")
    args = parser.parse_args(argv)
    try:
        if args.output and args.output.exists():
            raise ValueError("Output already exists; choose a new report path")
        with args.artifact.open("rb") as handle:
            data = handle.read(MAX_UPLOAD_BYTES + 1)
        result = scan_upload(data, args.artifact.name, args.target_runtime, source_channel=args.source_channel)
        rendered = json.dumps(result, ensure_ascii=True, indent=2) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(rendered)
        else:
            print(rendered, end="")
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as exc:
        parser.error(str(exc))
    # Exit 2 is argparse failure; distinguish findings from incomplete evidence.
    if result["readiness"]["status"] == "needs_review":
        return 1
    if result["coverage"]["status"] == "partial":
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
