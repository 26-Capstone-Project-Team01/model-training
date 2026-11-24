"""Install-hook command derivations shared by sanitize_manifests.py and manifest_analysis.py (no package code is executed)."""
from __future__ import annotations
import hashlib
import re

HOOKS = ("preinstall", "install", "postinstall")
ALL_HOOK_KEYS = ("preinstall", "install", "postinstall", "prepare")
FAMILY = [  # first matching rule wins; generic program families only (no malware package names)
    ("native_build", r"\b(node-gyp|node-gyp-build|prebuild-install|cmake-js|node-pre-gyp|prebuildify|napi|neon|cargo)\b"),
    ("husky_patch_setup", r"\b(husky|patch-package|is-ci|lefthook|simple-git-hooks|opencollective|ngcc|electron-builder|playwright|cypress|puppeteer)\b"),
    ("download_tool", r"\b(curl|wget|Invoke-WebRequest|iwr|certutil|bitsadmin)\b"),
    ("shell_exec", r"\b(bash|sh|powershell|pwsh|cmd)\b(\s|$)"),
    ("node_script", r"\bnode\b|\bbun\b|\bdeno\b"),
]
HIDES = r"(?:>\s*/dev/null|2>&1|\|\|\s*(?:true|exit 0)|\bnohup\b|&\s*$|-WindowStyle\s+Hidden)"


def new_hook_cmd(row) -> str:
    """preinstall/install/postinstall commands of the new version that are new or changed vs old, joined with ' && '."""
    return " && ".join(row[f"new_{h}"] for h in HOOKS if row[f"new_{h}"] and row[f"new_{h}"] != row[f"old_{h}"])


def family(cmd: str) -> str:
    if not cmd:
        return ""
    for name, pat in FAMILY:
        if re.search(pat, cmd):
            return name
    return "other"


def derive(cmd: str) -> dict:
    return {"hook_family": family(cmd), "hook_has_url": bool(re.search(r"https?://", cmd)), "hook_hides_output": bool(re.search(HIDES, cmd)),
            "hook_tokens": len(cmd.split()), "new_hook_cmd_sha256": hashlib.sha256(cmd.encode()).hexdigest() if cmd else ""}
