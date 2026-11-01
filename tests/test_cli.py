import json
from unittest.mock import patch

import pytest

from cve_detector.cli import main
from cve_detector.detector import error_report
from cve_detector.models import Report, Status


@pytest.mark.parametrize(
    "status,code",
    [
        (Status.NOT_VULNERABLE, 0),
        (Status.VULNERABLE, 1),
        (Status.INCONCLUSIVE, 2),
        (Status.ERROR, 3),
    ],
)
def test_json_schema_and_exit_codes(status, code, capsys):
    result = Report(
        "fixture",
        status,
        "runtime_binary",
        "Synthetic fixture",
        "sha256_identity",
        "Test only",
        {},
        ("Not a real scan",),
    )
    with patch("cve_detector.cli.detect", return_value=result):
        assert main(["--target", "fixture", "--format", "json"]) == code
    raw = json.loads(capsys.readouterr().out)
    assert raw["status"] == status and raw["schema_version"] == 1
    assert raw["cve"] == "CVE-2026-111497"
    assert raw["timestamp"].endswith("+00:00")
    assert raw["references"] and raw["limitations"] and raw["confidence"]


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--unknown", "secret"],
        ["--target", "fixture", "--retries", "3"],
        ["--target", "fixture", "--timeout", "nan"],
        ["--target", "fixture", "--timeout", "inf"],
        ["--target", "fixture", "--timeout", "-1"],
        ["--target", "fixture", "--verbose", "--quiet"],
        ["--tar", "fixture"],
    ],
)
def test_usage_errors_json_and_redacted(args, capsys):
    assert main(args + ["--format=json"]) == 3
    output = capsys.readouterr().out
    assert json.loads(output)["status"] == "ERROR"
    assert "secret" not in output


def test_real_unknown_file_and_output(tmp_path, capsys):
    path = tmp_path / "node"
    path.write_bytes(b"fixture")
    output = tmp_path / "report.json"
    assert main(["--target", str(path), "--format=json", "--output", str(output)]) == 2
    assert output.read_text() == capsys.readouterr().out
    assert json.loads(output.read_text())["status"] == "INCONCLUSIVE"


def test_output_cannot_overwrite_target(tmp_path, capsys):
    path = tmp_path / "node"
    path.write_bytes(b"fixture")
    assert main(["--target", str(path), "--format=json", "--output", str(path)]) == 3
    assert path.read_bytes() == b"fixture"
    assert json.loads(capsys.readouterr().out)["status"] == "ERROR"


def test_quiet_json_stays_complete(capsys):
    with patch("cve_detector.cli.detect", return_value=error_report("Test")):
        assert main(["--target", "fixture", "--format=json", "--quiet"]) == 3
    assert json.loads(capsys.readouterr().out)["cve"] == "CVE-2026-111497"


def test_console_quiet(capsys):
    with patch("cve_detector.cli.detect", return_value=error_report("Test")):
        assert main(["--target", "fixture", "--quiet"]) == 3
    assert capsys.readouterr().out == "ERROR\n"


@pytest.mark.parametrize("exception", [KeyboardInterrupt(), RuntimeError("secret")])
def test_interrupt_and_unexpected_errors(exception, capsys):
    with patch("cve_detector.cli.detect", side_effect=exception):
        assert main(["--target", "fixture", "--format=json"]) == 3
    text = capsys.readouterr().out
    assert json.loads(text)["status"] == "ERROR" and "secret" not in text


@pytest.mark.parametrize("option", ["--help", "--version"])
def test_help_and_version(option):
    with pytest.raises(SystemExit) as exc:
        main([option])
    assert exc.value.code == 0
