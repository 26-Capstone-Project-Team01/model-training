"""Remove install-hook command text of malicious rows from hook_commands.py output; keep derived hook categories,
a sha256 of the changed-hook command (for reproduction checks) and the identification columns.
Non-malicious rows keep their hook commands. Dependency columns are kept (needed for dependency_candidates).

Usage: python -I -B sanitize_manifests.py --raw <hook_commands.py manifests_summary.csv> --out <sanitized csv>
"""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
import sys
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hookfam  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    M = pd.read_csv(a.raw, keep_default_na=False, dtype=str)
    d = pd.DataFrame([hookfam.derive(hookfam.new_hook_cmd(r)) if r["manifest_ok"] == "True" else
                      {"hook_family": "", "hook_has_url": "", "hook_hides_output": "", "hook_tokens": "", "new_hook_cmd_sha256": ""} for _, r in M.iterrows()])
    M = pd.concat([M, d], axis=1)
    mal = M["class"] == "malicious"
    for side in ("old", "new"):
        for h in hookfam.ALL_HOOK_KEYS:
            M.loc[mal, f"{side}_{h}"] = ""
    M["hook_text_removed"] = mal
    M.to_csv(a.out, index=False, lineterminator="\n")
    print(json.dumps({"raw_sha256": hashlib.sha256(a.raw.read_bytes()).hexdigest(), "out_sha256": hashlib.sha256(a.out.read_bytes()).hexdigest(),
                      "rows": len(M), "malicious_rows_text_removed": int(mal.sum())}))


if __name__ == "__main__":
    main()
