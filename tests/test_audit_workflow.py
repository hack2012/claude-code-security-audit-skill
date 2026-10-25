"""Exercise the public CLI in disposable projects; no installed scanners required."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "plugins/security-audit/skills/security-audit/scripts/audit_workflow.py"
)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.root = self.home / "project"
        self.root.mkdir()
        self.rules = self.write_json(
            "rules.json",
            {
                "rules": [
                    {
                        "id": "unsafe-eval",
                        "pattern": r"eval\(",
                        "include": ["*.py"],
                        "message": "Review dynamic evaluation",
                        "level": "warning",
                    }
                ]
            },
        )

    def write_json(self, name, value):
        path = self.home / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def cli(self, *args, code=0):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *map(str, args)],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, code, result.stderr)
        if code == 2:
            self.assertEqual(result.stdout, "")
            self.assertNotIn("Traceback", result.stderr)
            return result
        return json.loads(result.stdout)

    def scan(self, code=0):
        return self.cli("scan", "--root", self.root, "--rules", self.rules, code=code)

    def sarif(self, results=None, tool="Semgrep", **run_extra):
        run = {
            "tool": {
                "driver": {
                    "name": tool,
                    "rules": [
                        {
                            "id": "unsafe-eval",
                            "defaultConfiguration": {"level": "warning"},
                        }
                    ],
                }
            },
            "results": results
            if results is not None
            else [
                {
                    "ruleId": "unsafe-eval",
                    "message": {"text": "SECRET_CANARY_8379"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/app%20file.py"},
                                "region": {"startLine": 3},
                            }
                        }
                    ],
                }
            ],
        }
        run.update(run_extra)
        return {"version": "2.1.0", "runs": [run]}

    def imported(self, data, code=0):
        return self.cli(
            "import-sarif",
            "--root",
            self.root,
            "--input",
            self.write_json("scan.sarif", data),
            code=code,
        )

    def compare(self, baseline, current, *extra, code=0):
        return self.cli(
            "monitor",
            "--baseline",
            self.write_json("baseline.json", baseline),
            "--current",
            self.write_json("current.json", current),
            *extra,
            code=code,
        )

    def test_scan_reports_line_without_leaking_source(self):
        (self.root / "app.py").write_text("# comment\neval('SECRET_CANARY_8379')\n")
        result = self.scan()
        self.assertEqual(result["schema_version"], 1)
        (finding,) = result["findings"]
        self.assertEqual(
            (finding["path"], finding["line"], finding["rule_id"]),
            ("app.py", 2, "unsafe-eval"),
        )
        self.assertEqual(finding["scanner_level"], "warning")
        self.assertEqual(finding["cvss_status"], "Unscored")
        self.assertNotIn("SECRET_CANARY_8379", json.dumps(result))
        self.assertEqual(self.scan(), result)

    def test_scan_includes_nested_files_and_excludes_git_and_symlinks(self):
        (self.root / "src").mkdir()
        (self.root / "src/app.py").write_text("eval('input')\n")
        (self.root / ".git").mkdir()
        (self.root / ".git/hidden.py").write_text("eval('hidden')\n")
        outside = self.home / "outside.py"
        outside.write_text("eval('outside')\n")
        (self.root / "linked.py").symlink_to(outside)
        (self.root / "linked-dir").symlink_to(self.home, target_is_directory=True)
        self.assertEqual([f["path"] for f in self.scan()["findings"]], ["src/app.py"])

    def test_scan_clean_project(self):
        (self.root / "app.py").write_text("print('hello')\n")
        self.assertEqual(self.scan()["findings"], [])

    def test_plain_clone_install_can_run_the_same_helper(self):
        alias = Path(__file__).resolve().parents[1] / "scripts/audit_workflow.py"
        result = subprocess.run(
            [
                sys.executable,
                str(alias),
                "scan",
                "--root",
                str(self.root),
                "--rules",
                str(self.rules),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), self.scan())

    def test_rules_reject_invalid_regex_duplicate_ids_and_commands(self):
        original = json.loads(self.rules.read_text())
        for variant in ("regex", "duplicate", "command"):
            with self.subTest(variant=variant):
                rules = json.loads(json.dumps(original))
                if variant == "regex":
                    rules["rules"][0]["pattern"] = "["
                elif variant == "duplicate":
                    rules["rules"] *= 2
                else:
                    rules["rules"][0]["command"] = "touch should-not-exist"
                self.rules.write_text(json.dumps(rules))
                self.scan(code=2)
        self.assertFalse((self.root / "should-not-exist").exists())

    def test_scan_rejects_incomplete_oversized_or_non_utf8_input(self):
        path = self.root / "app.py"
        for content in (b"\xff", b"x" * (1024 * 1024 + 1)):
            with self.subTest(size=len(content)):
                path.write_bytes(content)
                self.scan(code=2)

    def test_sarif_semgrep_and_codeql_are_unscored_and_redacted(self):
        data = self.sarif()
        data["runs"] += self.sarif(tool="CodeQL")["runs"]
        result = self.imported(data)
        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual({f["path"] for f in result["findings"]}, {"src/app file.py"})
        self.assertEqual({f["cvss_status"] for f in result["findings"]}, {"Unscored"})
        self.assertNotIn("SECRET_CANARY_8379", json.dumps(result))

    def test_sarif_rule_index_and_default_level(self):
        data = self.sarif()
        result = data["runs"][0]["results"][0]
        del result["ruleId"]
        result["ruleIndex"] = 0
        (finding,) = self.imported(data)["findings"]
        self.assertEqual(finding["rule_id"], "unsafe-eval")
        self.assertEqual(finding["scanner_level"], "warning")

    def test_sarif_rejects_paths_outside_root(self):
        for uri in (
            "../secret.py",
            "%2e%2e/secret.py",
            "file:///etc/passwd",
            "https://evil.example/app.py",
        ):
            with self.subTest(uri=uri):
                data = self.sarif()
                data["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
                    "artifactLocation"
                ]["uri"] = uri
                self.imported(data, code=2)

    def test_sarif_rejects_failed_scans_and_missing_locations(self):
        for data in (
            self.sarif(invocations=[{"executionSuccessful": False}]),
            self.sarif(results=[{"ruleId": "r", "message": {"text": "bad"}}]),
            {"version": "2.1.0", "runs": []},
            {"version": "1.0", "runs": []},
        ):
            with self.subTest(data=data):
                self.imported(data, code=2)

    def test_sarif_empty_success_is_clean(self):
        self.assertEqual(self.imported(self.sarif(results=[]))["findings"], [])

    def test_sarif_incomplete_run_is_not_clean(self):
        data = self.sarif()
        del data["runs"][0]["results"]
        self.imported(data, code=2)

    def test_sarif_artifact_indices_and_absolute_uri_base(self):
        data = self.sarif()
        run = data["runs"][0]
        run["originalUriBaseIds"] = {"SRCROOT": {"uri": self.root.as_uri() + "/"}}
        run["artifacts"] = [{"location": {"uri": "src/app.py", "uriBaseId": "SRCROOT"}}]
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {
            "index": 0
        }
        self.assertEqual(self.imported(data)["findings"][0]["path"], "src/app.py")

    def test_real_semgrep_srcroot_without_base_definition(self):
        # Semgrep 1.182.1 emits %SRCROOT% without originalUriBaseIds.
        for uri in (str(self.root / "app.py"), "app.py"):
            with self.subTest(uri=uri):
                data = self.sarif(
                    invocations=[
                        {
                            "executionSuccessful": True,
                            "toolExecutionNotifications": [],
                        }
                    ]
                )
                physical = data["runs"][0]["results"][0]["locations"][0][
                    "physicalLocation"
                ]
                physical["artifactLocation"] = {"uri": uri, "uriBaseId": "%SRCROOT%"}
                self.assertEqual(self.imported(data)["findings"][0]["path"], "app.py")

    def test_sarif_rejects_undefined_relative_base_and_srcroot_escape(self):
        for uri, base in (("app.py", "UNKNOWN"), ("../secret.py", "%SRCROOT%")):
            with self.subTest(uri=uri, base=base):
                data = self.sarif()
                physical = data["runs"][0]["results"][0]["locations"][0][
                    "physicalLocation"
                ]
                physical["artifactLocation"] = {"uri": uri, "uriBaseId": base}
                self.imported(data, code=2)

    def test_sarif_error_notifications_are_not_clean(self):
        data = self.sarif(
            results=[],
            invocations=[
                {
                    "executionSuccessful": True,
                    "toolExecutionNotifications": [
                        {"level": "error", "message": {"text": "SECRET_CANARY_8379"}}
                    ],
                }
            ],
        )
        result = self.imported(data, code=2)
        self.assertNotIn("SECRET_CANARY_8379", result.stderr)

    def test_monitor_rejects_changed_scanner_rules(self):
        data = self.sarif()
        before = self.imported(data)
        data["runs"][0]["tool"]["driver"]["rules"].append({"id": "different-query"})
        after = self.imported(data)
        self.compare(before, after, code=2)

    def test_snapshot_order_does_not_change_monitor_results(self):
        (self.root / "app.py").write_text("eval('one')\neval('two')\n")
        before = self.scan()
        after = {**before, "findings": list(reversed(before["findings"]))}
        result = self.compare(before, after)
        self.assertEqual(len(result["unchanged"]), 2)
        self.assertEqual(result["new"], [])
        self.assertEqual(result["resolved"], [])

    def test_monitor_classifies_new_resolved_and_unchanged(self):
        (self.root / "app.py").write_text("eval('old')\n")
        before = self.scan()
        (self.root / "new.py").write_text("eval('new')\n")
        after = self.scan()
        delta = self.compare(before, after, "--fail-on-new", code=1)
        self.assertEqual([f["path"] for f in delta["new"]], ["new.py"])
        self.assertEqual([f["path"] for f in delta["unchanged"]], ["app.py"])
        self.assertEqual(delta["resolved"], [])
        delta = self.compare(after, before)
        self.assertEqual([f["path"] for f in delta["resolved"]], ["new.py"])
        self.assertEqual(json.loads((self.home / "baseline.json").read_text()), after)

    def test_monitor_rejects_scope_mismatch_and_invalid_documents(self):
        before = self.scan()
        changed = json.loads(json.dumps(before))
        changed["coverage"]["rules_digest"] = "different"
        self.compare(before, changed, code=2)
        self.compare(before, {"findings": []}, code=2)
        self.compare(before, {**before, "schema_version": 99}, code=2)

    def test_monitor_rejects_duplicate_fingerprints(self):
        (self.root / "app.py").write_text("eval('old')\n")
        before = self.scan()
        duplicate = {**before, "findings": before["findings"] * 2}
        self.compare(before, duplicate, code=2)

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.root), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def test_patch_check_does_not_apply_changes_and_rejects_bad_patch(self):
        self.git("init", "-q")
        (self.root / "app.py").write_text("eval('input')\n")
        self.git("add", "app.py")
        self.git(
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture",
        )
        (self.root / "app.py").write_text("print('input')\n")
        patch = self.home / "fix.patch"
        patch.write_text(self.git("diff"))
        self.git("restore", "app.py")
        baseline = self.scan()
        before = self.git("status", "--porcelain")
        result = self.cli("check-patch", "--root", self.root, "--patch", patch)
        self.assertTrue(result["applicable"])
        self.assertEqual((self.root / "app.py").read_text(), "eval('input')\n")
        self.assertEqual(self.git("status", "--porcelain"), before)
        # Exercise the authorized remediation workflow separately from the
        # read-only helper: apply the reviewed patch, rescan, compare evidence.
        self.git("apply", str(patch))
        current = self.scan()
        self.assertEqual(current["findings"], [])
        delta = self.compare(baseline, current)
        self.assertEqual(len(delta["resolved"]), 1)
        self.assertEqual(delta["new"], [])
        patch.write_text("invalid patch")
        self.cli("check-patch", "--root", self.root, "--patch", patch, code=2)

    def test_missing_inputs_are_actionable_errors(self):
        self.cli("scan", "--root", self.home / "missing", "--rules", self.rules, code=2)
        self.rules.write_text("{bad-json")
        self.scan(code=2)


if __name__ == "__main__":
    unittest.main()
