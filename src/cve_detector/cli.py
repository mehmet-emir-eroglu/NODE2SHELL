"""Validated command-line entry point with stable JSON errors and exit codes."""

import argparse
import logging
import math
import sys
from pathlib import Path
from typing import NoReturn

from . import __version__
from .detector import detect, error_report
from .exceptions import DetectionError
from .models import EXIT_CODES
from .output import render, write_report


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise DetectionError("Invalid or missing arguments; use --help for supported options.")


def parser() -> argparse.ArgumentParser:
    result = Parser(
        allow_abbrev=False,
        description=(
            "Read-only Node2Shell (CVE-2026-111497) verification of local Node.js binaries "
            "and release files. Findings concern code identity, not application exploitability."
        ),
    )
    result.add_argument(
        "--target", required=True, help="Local Node.js binary, installer or archive"
    )
    result.add_argument(
        "--release", help="Exact Node.js version; permits nodejs.org lookup if needed"
    )
    result.add_argument(
        "--timeout", type=float, default=5, help="Metadata socket timeout 0.1..30; default 5"
    )
    result.add_argument(
        "--retries", type=int, default=0, help="Extra metadata attempts 0..2; default 0"
    )
    result.add_argument("--format", choices=("console", "json"), default="console")
    result.add_argument(
        "--output", type=Path, help="Create a new report; never overwrite an existing file"
    )
    group = result.add_mutually_exclusive_group()
    group.add_argument("--verbose", action="store_true", help="Progress on stderr")
    group.add_argument(
        "--quiet", action="store_true", help="Console status only; JSON stays complete"
    )
    result.add_argument("--version", action="version", version=__version__)
    return result


def main(argv: list[str] | None = None) -> int:
    words = list(sys.argv[1:] if argv is None else argv)
    requested_json = "--format=json" in words or any(
        words[i : i + 2] == ["--format", "json"] for i in range(len(words))
    )
    output_format = "json" if requested_json else "console"
    try:
        args = parser().parse_args(words)
        output_format = args.format
        if not math.isfinite(args.timeout) or not 0.1 <= args.timeout <= 30:
            raise DetectionError("--timeout must be finite and between 0.1 and 30 seconds.")
        if not 0 <= args.retries <= 2:
            raise DetectionError("--retries must be between 0 and 2.")
        logging.basicConfig(
            level=logging.INFO if args.verbose else logging.WARNING,
            format="%(levelname)s: %(message)s",
        )
        result = detect(args.target, args.release, args.timeout, args.retries)
        text = render(result, output_format, args.quiet)
        if args.output:
            write_report(args.output, text)
    except DetectionError as exc:
        result = error_report(str(exc))
        text = render(result, output_format)
    except KeyboardInterrupt:
        result = error_report("Assessment interrupted by user.")
        text = render(result, output_format)
    except Exception:
        result = error_report("Unexpected internal failure; report a sanitized reproduction.")
        text = render(result, output_format)
    try:
        sys.stdout.write(text)
    except (OSError, UnicodeError):
        return 3
    return EXIT_CODES[result.status]
