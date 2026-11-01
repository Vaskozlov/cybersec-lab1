"""Build the report only when the attached CI evidence confirms success."""
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "output" / "evidence"


def main():
    ci = json.loads((EVIDENCE / "ci-result.json").read_text())
    assert ci["conclusion"] == "success", "CI has not succeeded"
    assert ci["sast_conclusion"] == ci["sca_conclusion"] == "success"
    assert ci["action_warning_count"] == 0, "Review unresolved CI warnings before building"
    assert ci["npm_total"] == ci["vulnerable_dependencies"] == 0
    report = json.loads((EVIDENCE / "dependency-check-report.json").read_text())
    assert not report["scanInfo"].get("analysisExceptions"), "Scanner analysis errors"
    assert len(report["dependencies"]) == ci["dependencies"]
    assert all(not entry.get("vulnerabilities") for entry in report["dependencies"])
    lint = json.loads((EVIDENCE / "eslint.json").read_text())
    assert lint and sum(entry["errorCount"] + entry["warningCount"] for entry in lint) == 0
    for name in ("sast", "sca"):
        log = (EVIDENCE / f"actions-{name}.log").read_text()
        assert not re.search(r"##\[warning\]|DeprecationWarning:|ExperimentalWarning:|\[WARN\]|npm warn", log, re.I)
    for name in ("actions-summary.jpg", "actions-sast.jpg", "actions-sca.jpg"):
        assert (ROOT / "output" / "screenshots" / name).is_file(), f"Missing screenshot: {name}"
    if not shutil.which("typst"):
        raise RuntimeError("Install Typst to build the PDF")
    destination = ROOT / "output" / "pdf" / "otchet_lab1_secure_api_kozlov.pdf"
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["typst", "compile", "report.typ", str(destination)], cwd=ROOT, check=True)
    print(destination)


if __name__ == "__main__":
    main()
