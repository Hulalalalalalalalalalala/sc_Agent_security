"""Milestone 5 Independent QA & Public GitHub Pre-Push Compliance Suite.

Strictly read-only verification of:
1. `[HIGH-M5-01]` `.gitignore` exclusions (`*.jwt`, `t1-signing-input.txt`, `lab/bin/python3`),
   `push_to_github.sh` symlink/JWT/private-key gates, and `lineage/` package layout preservation
   under both `--scope workspace` and `--scope lineage-only`.
2. `[MEDIUM-M5-01]` Rust SDK & reference server bounds (`MAX_HEADER_LINES`, `MAX_BODY_BYTES`,
   pre-allocation auth check, RFC 8259 `json_escape`, short `LCT_LOOPBACK_SECRET` rejection).
3. `[MEDIUM-M5-02]` Length-hiding SHA-256 constant-time loopback secret verification & `>=16`-char
   secret enforcement across Python, Go, Node.js, Java, and Rust SDKs + 2/2 Pod manifest isolation.
4. `[MEDIUM-M5-03]` & `[LOW-M5-01]` `pyproject.toml` in-root package mapping (`package-dir`) and
   `configure_agent_lang.sh` DNS-1123 / skill / NodePort `[30000, 32767]` input validation.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import unittest
import yaml

from lineage.sdk.python.lct_sdk import load_loopback_secret, verify_loopback_secret

REPO_ROOT = Path("/Users/hulalala/Desktop/A")
LINEAGE_DIR = REPO_ROOT / "lineage"
SCRIPTS_DIR = LINEAGE_DIR / "scripts"
SDK_DIR = LINEAGE_DIR / "sdk"


def _tool_env() -> dict[str, str]:
    env = dict(os.environ)
    extra = [
        str(REPO_ROOT / ".tools" / "bin"),
        str(REPO_ROOT / ".tools" / "ollama"),
        str(Path.home() / ".local" / "bin"),
        str(Path.home() / ".docker" / "bin"),
        "/opt/homebrew/bin",
        "/usr/local/bin",
    ]
    env["PATH"] = ":".join(extra + [env.get("PATH", "")])
    return env


class Milestone5PublicPushAndPolyglotQASignoff(unittest.TestCase):
    def test_01_public_repo_dry_run_exclusions_and_package_layout(self) -> None:
        env = _tool_env()
        push_script = SCRIPTS_DIR / "push_to_github.sh"

        for scope in ("workspace", "lineage-only"):
            res = subprocess.run(
                ["bash", str(push_script), "--scope", scope, "--dry-run"],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("0 symlinks; 0 files > 50 MB", res.stdout)
            self.assertIn(
                "Secret Audit  : PASS (0 private keys, 0 GitHub PATs, 0 raw JWTs, 0 raw LCT run tokens)",
                res.stdout,
            )

        # Confirm dry-run left zero .git directories behind
        self.assertFalse((REPO_ROOT / ".git").exists())
        self.assertFalse((LINEAGE_DIR / ".git").exists())

        # Inspect exact staged paths in a throwaway git index for both scopes
        for scope, stage_items in (
            ("workspace", [".gitignore", "README.md", "lab", "lineage"]),
            ("lineage-only", [".gitignore", "lineage"]),
        ):
            with tempfile.TemporaryDirectory() as td:
                gdir = Path(td) / "gitdir"
                subprocess.run(
                    ["git", f"--git-dir={gdir}", f"--work-tree={REPO_ROOT}", "init", "-q"],
                    env=env,
                    check=True,
                )
                subprocess.run(
                    ["git", f"--git-dir={gdir}", f"--work-tree={REPO_ROOT}", "add", *stage_items],
                    env=env,
                    check=True,
                )
                staged = set(
                    subprocess.check_output(
                        ["git", f"--git-dir={gdir}", f"--work-tree={REPO_ROOT}", "ls-files"],
                        env=env,
                        text=True,
                    ).splitlines()
                )
                # Must preserve `lineage/` top-level Python package prefix in BOTH scopes!
                self.assertIn("lineage/__init__.py", staged)
                self.assertIn("lineage/common/crypto.py", staged)
                self.assertIn("lineage/k8s/Dockerfile", staged)
                self.assertIn("lineage/scripts/setup_deps.sh", staged)

                # Must strictly exclude `.tools/`, `src/`, `lab/bin/python3`, `*.jwt`, `t1-signing-input.txt`
                for s in staged:
                    self.assertFalse(s.startswith((".tools/", "src/")), s)
                    self.assertFalse(s.endswith(".jwt"), s)
                    self.assertNotIn("t1-signing-input.txt", s)
                    self.assertNotEqual(s, "lab/bin/python3")

                if scope == "workspace":
                    self.assertIn("README.md", staged)
                    self.assertIn(
                        "lab/reviews/2026-11-17/token-walkthrough-093330/keycloak-signing-public.pem",
                        staged,
                    )
                else:
                    self.assertFalse(any(s.startswith("lab/") for s in staged))

    def test_02_push_to_github_blocks_leaked_jwt_private_key_and_symlink(self) -> None:
        env = _tool_env()
        src_push = (SCRIPTS_DIR / "push_to_github.sh").read_text(encoding="utf-8")

        def _run_isolated_push(mutate_fn) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as td:
                fake_root = Path(td)
                (fake_root / ".gitignore").write_text(".tools/\n", encoding="utf-8")
                (fake_root / "lineage" / "common").mkdir(parents=True)
                (fake_root / "lineage" / "scripts").mkdir(parents=True)
                (fake_root / "lineage" / "common" / "__init__.py").write_text("", encoding="utf-8")
                script_copy = fake_root / "lineage" / "scripts" / "push_to_github.sh"
                script_copy.write_text(src_push, encoding="utf-8")
                mutate_fn(fake_root)
                return subprocess.run(
                    ["bash", str(script_copy), "--scope", "lineage-only", "--dry-run"],
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )

        # 1. Synthetic 3-part JWT (constructed dynamically so source file has zero literal tokens)
        fake_jwt = "eyJ" + ("a" * 16) + "." + ("b" * 16) + "." + ("c" * 16)
        r_jwt = _run_isolated_push(
            lambda root: (root / "lineage" / "leaked.txt").write_text(fake_jwt, encoding="utf-8")
        )
        self.assertNotEqual(r_jwt.returncode, 0)
        self.assertIn("Raw 3-part JWT/JWS token detected", r_jwt.stderr)

        # 2. Synthetic PEM private key header (constructed dynamically)
        fake_pem = "-----BEGIN " + "EC PRIVATE KEY-----\nMIIB...\n"
        r_pem = _run_isolated_push(
            lambda root: (root / "lineage" / "leaked_key.txt").write_text(fake_pem, encoding="utf-8")
        )
        self.assertNotEqual(r_pem.returncode, 0)
        self.assertIn("Private key or GitHub token detected", r_pem.stderr)

        # 3. Host symlink staged into repo
        r_sym = _run_isolated_push(
            lambda root: os.symlink("/bin/sh", root / "lineage" / "host_link")
        )
        self.assertNotEqual(r_sym.returncode, 0)
        self.assertIn("Host symlink must not be staged", r_sym.stderr)

    def test_03_polyglot_sdk_constant_time_and_secret_length_enforcement(self) -> None:
        env = _tool_env()
        good_secret = "s3cr3t-loopback-token-0123456789abcdef"

        # 1. Python SDK checks
        self.assertTrue(verify_loopback_secret(good_secret, good_secret))
        self.assertFalse(verify_loopback_secret(good_secret[:-1], good_secret))
        self.assertFalse(verify_loopback_secret(good_secret + "x", good_secret))
        self.assertFalse(verify_loopback_secret("", good_secret))
        self.assertFalse(verify_loopback_secret(None, good_secret))

        old_inline = os.environ.get("LCT_LOOPBACK_SECRET")
        try:
            os.environ["LCT_LOOPBACK_SECRET"] = "too-short"
            with self.assertRaises(ValueError):
                load_loopback_secret()
            os.environ["LCT_LOOPBACK_SECRET"] = good_secret
            self.assertEqual(load_loopback_secret(), good_secret)
        finally:
            if old_inline is None:
                os.environ.pop("LCT_LOOPBACK_SECRET", None)
            else:
                os.environ["LCT_LOOPBACK_SECRET"] = old_inline

        # 2. Node.js SDK checks (unequal buffer lengths MUST return false cleanly, never RangeError)
        node_bin = shutil.which("node", path=env["PATH"])
        self.assertIsNotNone(node_bin)
        node_mjs = (SDK_DIR / "node" / "lct_sdk.mjs").as_uri()
        node_script = f"""
import assert from "node:assert/strict";
import {{ verifyLoopbackHeader, loadLoopbackSecret }} from "{node_mjs}";
const s = "{good_secret}";
assert.equal(verifyLoopbackHeader(s, s), true);
assert.equal(verifyLoopbackHeader("x", s), false);
assert.equal(verifyLoopbackHeader(s + "-extra-bytes", s), false);
assert.equal(verifyLoopbackHeader("", s), false);
assert.equal(verifyLoopbackHeader(undefined, s), false);
process.env.LCT_LOOPBACK_SECRET = "short123";
assert.throws(() => loadLoopbackSecret(), /at least 16/);
process.env.LCT_LOOPBACK_SECRET = s;
assert.equal(loadLoopbackSecret(), s);
"""
        r_node = subprocess.run(
            [str(node_bin), "--input-type=module", "-e", node_script],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(r_node.returncode, 0, r_node.stderr)

        # 3. Go SDK checks
        go_bin = shutil.which("go", path=env["PATH"])
        self.assertIsNotNone(go_bin)
        with tempfile.TemporaryDirectory() as td:
            go_test_dir = Path(td) / "gotest"
            shutil.copytree(SDK_DIR / "go", go_test_dir)
            (go_test_dir / "lctsdk" / "sdk_qa_test.go").write_text(
                """package lctsdk

import (
	"os"
	"testing"
)

func TestVerifyAndLoadLoopback(t *testing.T) {
	s := "s3cr3t-loopback-token-0123456789abcdef"
	if !VerifyLoopbackHeader(s, s) {
		t.Fatal("expected exact match true")
	}
	for _, bad := range []string{"", "short", s[:len(s)-1], s + "extra"} {
		if VerifyLoopbackHeader(bad, s) {
			t.Fatalf("unexpected match for %q", bad)
		}
	}
	t.Setenv("LCT_LOOPBACK_SECRET", "short123")
	if _, err := LoadLoopbackSecret(""); err == nil {
		t.Fatal("expected error for short LCT_LOOPBACK_SECRET")
	}
	os.Unsetenv("LCT_LOOPBACK_SECRET")
}
""",
                encoding="utf-8",
            )
            r_go = subprocess.run(
                [str(go_bin), "test", "./..."],
                cwd=str(go_test_dir),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_go.returncode, 0, r_go.stdout + r_go.stderr)

        # 4. Rust & Java SDK static invariants + all 5 k8s-2of2-pod.yaml checks
        rust_lib = (SDK_DIR / "rust" / "src" / "lib.rs").read_text(encoding="utf-8")
        rust_main = (SDK_DIR / "rust" / "src" / "main.rs").read_text(encoding="utf-8")
        self.assertIn("pub fn json_escape", rust_lib)
        self.assertIn("a.len() ^ b.len()", rust_lib)
        self.assertIn("MAX_HEADER_LINES", rust_main)
        self.assertIn("MAX_BODY_BYTES", rust_main)
        # Verify auth check precedes body allocation in main.rs
        self.assertLess(
            rust_main.index("verify_loopback_secret(provided, &secret)"),
            rust_main.index("vec![0u8; content_len]"),
        )
        self.assertIn("json_escape(&ctx.task_id)", rust_main)

        java_src = (SDK_DIR / "java" / "LCTSidecarClient.java").read_text(encoding="utf-8")
        self.assertIn('MessageDigest.getInstance("SHA-256")', java_src)
        self.assertIn("MessageDigest.isEqual(dProv, dExp)", java_src)
        self.assertIn("LCT_LOOPBACK_SECRET must be >= 16 chars", java_src)

        for lang in ("python", "go", "node", "java", "rust"):
            manifest_path = SDK_DIR / lang / "k8s-2of2-pod.yaml"
            with open(manifest_path, "r", encoding="utf-8") as mf:
                docs = [d for d in yaml.safe_load_all(mf) if d]
            sa_doc, dep_doc = docs[0], docs[1]
            self.assertIs(sa_doc["automountServiceAccountToken"], False)
            pod_spec = dep_doc["spec"]["template"]["spec"]
            self.assertIs(pod_spec["automountServiceAccountToken"], False)
            containers = {c["name"]: c for c in pod_spec["containers"]}
            app_mounts = [m["name"] for m in containers["app"]["volumeMounts"]]
            self.assertEqual(app_mounts, ["lct-loopback"])

    def test_04_scaffolder_input_validation_spaces_and_pyproject_metadata(self) -> None:
        env = _tool_env()
        scaffolder = SCRIPTS_DIR / "configure_agent_lang.sh"

        with tempfile.TemporaryDirectory() as td:
            spaced_target = Path(td) / "dir with spaces" / "rust agent"
            ok_res = subprocess.run(
                [
                    "bash",
                    str(scaffolder),
                    "--lang",
                    "rust",
                    "--target",
                    str(spaced_target),
                    "--name",
                    "valid-rust-agent",
                    "--domain",
                    "org-alpha.io",
                    "--skill",
                    "travel.rust.guard",
                    "--nodeport",
                    "30499",
                ],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(ok_res.returncode, 0, ok_res.stderr)
            self.assertTrue((spaced_target / "k8s-2of2-pod.yaml").is_file())

            # Invalid --name, --skill, and --nodeport must all fail with exit code 2
            bad_cases = [
                ["--lang", "go", "--target", str(Path(td) / "b1"), "--name", "Invalid_Upper"],
                ["--lang", "go", "--target", str(Path(td) / "b2"), "--name", "bad;inject"],
                ["--lang", "go", "--target", str(Path(td) / "b3"), "--skill", 'bad"quote'],
                ["--lang", "go", "--target", str(Path(td) / "b4"), "--nodeport", "8080"],
                ["--lang", "go", "--target", str(Path(td) / "b5"), "--nodeport", "39999"],
                ["--lang", "go", "--target", str(Path(td) / "b6"), "--nodeport", "notanint"],
            ]
            for args in bad_cases:
                bad_res = subprocess.run(
                    ["bash", str(scaffolder), *args],
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(
                    bad_res.returncode,
                    2,
                    f"Expected exit 2 for {args}, got {bad_res.returncode}: {bad_res.stderr}",
                )

        # Verify pyproject.toml maps `lineage` -> `.` without `..` parent traversal
        with open(LINEAGE_DIR / "pyproject.toml", "rb") as pf:
            pyproj = tomllib.load(pf)
        st_cfg = pyproj["tool"]["setuptools"]
        self.assertEqual(st_cfg["package-dir"], {"lineage": "."})
        self.assertIn("lineage", st_cfg["packages"])
        self.assertIn("lineage.sidecar", st_cfg["packages"])
        self.assertIn("lineage.sdk.python", st_cfg["packages"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
