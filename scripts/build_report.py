"""Build the report only when the attached CI evidence confirms success."""
import json
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "output" / "evidence"


def require(condition, message):
    # Explicit checks also run under python -O; report evidence must never be optional.
    if not condition:
        raise ValueError(message)


def parse_test_results(log):
    log = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", log).replace("\r\n", "\n")
    counters = {}
    for key, value in re.findall(r"^(?:ℹ )?(tests|pass|fail|cancelled|skipped|todo) (\d+)$", log, re.M):
        require(key not in counters, f"Duplicate test counter: {key}")
        counters[key] = int(value)
    require(len(counters) == 6, "Test runner summary is missing or incomplete")
    require(counters["tests"] > 0 and counters["pass"] == counters["tests"], "Tests did not all pass")
    require(all(counters[key] == 0 for key in ("fail", "cancelled", "skipped", "todo")),
            "Failed, cancelled, skipped or todo tests are not acceptable")
    return {
        "tests_total": counters["tests"], "tests_passed": counters["pass"],
        "tests_failed": counters["fail"], "tests_cancelled": counters["cancelled"],
        "tests_skipped": counters["skipped"], "tests_todo": counters["todo"],
    }


def validate_evidence(evidence=EVIDENCE, root=ROOT):
    ci = json.loads((evidence / "ci-result.json").read_text())
    require(ci["conclusion"] == "success", "CI has not succeeded")
    require(ci["sast_conclusion"] == ci["sca_conclusion"] == "success", "Security jobs did not succeed")
    run = json.loads((evidence / "ci-run.json").read_text())
    require(run["conclusion"] == "success" and run["head_sha"] == ci["head_sha"]
            and run["html_url"] == ci["run_url"], "CI run metadata does not match the summary")
    jobs = json.loads((evidence / "ci-jobs.json").read_text())["jobs"]
    expected_jobs = {"API tests and SAST", "SCA - OWASP Dependency-Check"}
    require({job["name"] for job in jobs} == expected_jobs, "Security jobs are missing")
    for job in jobs:
        require(job["run_id"] == run["id"] and job["head_sha"] == ci["head_sha"]
                and job["conclusion"] == "success", "CI job metadata does not match a successful run")
        require(all(step["conclusion"] == "success" for step in job["steps"]),
                "A CI step failed, was cancelled or was skipped")
    counts = parse_test_results((evidence / "tests.txt").read_text())
    for key, value in counts.items():
        require(ci.get(key) == value, f"CI summary does not match the test log: {key}")
    audit = json.loads((evidence / "npm-audit.json").read_text())
    require(not audit.get("error") and not audit["vulnerabilities"], "npm audit reported errors or vulnerabilities")
    require(audit["metadata"]["vulnerabilities"]["total"] == ci["npm_total"] == 0,
            "npm audit totals do not confirm zero vulnerabilities")
    report = json.loads((evidence / "dependency-check-report.json").read_text())
    require(not report["scanInfo"].get("analysisExceptions"), "Scanner analysis errors")
    dependencies = report["dependencies"]
    require(len(dependencies) == ci["dependencies"] > 0, "Dependency count is inconsistent")
    require(ci["vulnerable_dependencies"] == 0 and all(not entry.get("vulnerabilities") for entry in dependencies),
            "Dependency-Check reported vulnerabilities")
    packages = json.loads((root / "package-lock.json").read_text())["packages"]
    expected = {(path.rsplit("node_modules/", 1)[1], entry["version"])
                for path, entry in packages.items() if path}
    analyzed = {tuple(unquote(package["id"]).removeprefix("pkg:npm/").rsplit("@", 1))
                for entry in dependencies for package in entry.get("packages", [])}
    require(expected == analyzed, "Dependency-Check did not cover every locked package and version")
    require(audit["metadata"]["dependencies"]["total"] == len(packages) - 1,
            "npm audit did not cover every locked dependency")
    lint = json.loads((evidence / "eslint.json").read_text())
    require(lint and sum(entry["errorCount"] + entry["warningCount"] for entry in lint) == 0,
            "SAST did not produce a clean scan")
    require(len(lint) == ci["eslint_files"] and ci["eslint_errors"] == ci["eslint_warnings"] == 0,
            "SAST summary does not match its JSON report")
    for name in ("sast", "sca"):
        log = (evidence / f"actions-{name}.log").read_text()
        require(not re.search(r"##\[(?:warning|notice)\]|DeprecationWarning:|ExperimentalWarning:|\[WARN\]|npm (?:warn|notice)", log, re.I),
                f"Review unresolved CI warnings or notices in {name} logs")
    require(ci["action_warning_count"] == ci["action_notice_count"] == 0,
            "Review unresolved CI warnings or notices before building")
    return counts


def main():
    validate_evidence()
    for name in ("actions-summary.jpg", "actions-sast.jpg", "actions-sca.jpg"):
        require((ROOT / "output" / "screenshots" / name).is_file(), f"Missing screenshot: {name}")
    if not shutil.which("typst"):
        raise RuntimeError("Install Typst to build the PDF")
    destination = ROOT / "output" / "pdf" / "otchet_lab1_secure_api_kozlov.pdf"
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["typst", "compile", "report.typ", str(destination)], cwd=ROOT, check=True)
    print(destination)


if __name__ == "__main__":
    main()
