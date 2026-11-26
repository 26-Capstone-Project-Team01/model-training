"""Build the minimal preservation set (allowlist copy + sanitisation). No commit/push.
Sanitisation: install-hook command strings, 'nojs:' payload keys, webhook.site tokens, Telegram bot tokens -> sha1 tags."""
import hashlib, json, re, shutil, sys
import pandas as pd
from pathlib import Path
E = Path("/home/user/d08_m1m4_experiment"); A = E / "archive_d08_group_analysis"; OUT = E / "preserve_minimal"
assert not OUT.exists(); OUT.mkdir()
h = lambda s: hashlib.sha1(s.encode()).hexdigest()[:16]
RULES = [
    (re.compile(r"nojs:(?!')[^,\n\"]*(?:\"[^\"]*\")?[^,\n]*"), lambda m: "nojs:sha1:" + h(m.group(0))),
    (re.compile(r"\b(preinstall|postinstall|install)=[^,\n\"]*(?:\"[^\"]*\"[^,\n\"]*)*"), lambda m: f"{m.group(1)}=<redacted sha1:{h(m.group(0))}>"),
    (re.compile(r"webhook\.site/[0-9a-f-]{36}"), lambda m: "webhook.site/<redacted sha1:" + h(m.group(0)) + ">"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"), lambda m: ("<webhook-token sha1:" + h(m.group(0)) + ">") if h(m.group(0)) == "0c7553fed3f1e6aa" else m.group(0)),
    (re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"), lambda m: "<telegram-token sha1:" + h(m.group(0)) + ">"),
]
FILES = {  # dest: source
 "README.md": None, "REPORT.md": A / "REPORT.md",
 "evidence/EVIDENCE_SUMMARY.csv": A / "evidence/EVIDENCE_SUMMARY.csv",
 "evidence/rotpacker_decoded_payload_hashes.csv": A / "evidence/group_leakage/rotpacker_decoded_map.csv",
 "evidence/family_marker_hits.csv": A / "evidence/group_leakage/family_marker_hits.csv",
 "evidence/shared_malicious_only_blobs.csv": A / "evidence/group_leakage/shared_malicious_only_blobs.csv",
 "evidence/normal_baseline_signature_hits.csv": A / "evidence/group_leakage/normal_baseline_signature_hits.csv",
 "evidence/evidence_links_G2f.csv": A / "evidence/group_leakage/out6_links_G2f.csv",
 "evidence/d08_analysis/summary.json": A / "evidence/d08_analysis/out1_analysis/summary.json",
 "mappings/merge_G1.json": A / "mappings/merge_G1.json", "mappings/merge_G2.json": A / "mappings/merge_G2.json", "mappings/merge_G2f.json": E / "g2f/config/merge_G2f.json",
 "mappings/dev_exclusion_clipper6.csv": E / "g2f/config/dev_exclusion_clipper6.csv",
 "mappings/group_mapping_G0_to_G2f_summary.csv": E / "g2f/config/group_mapping_G0_to_G2f_summary.csv",
 "mappings/group_mapping_G0_to_G2f_rows.csv": E / "g2f/config/group_mapping_G0_to_G2f_rows.csv",
 "code/run_m1m4.py": E / "run_m1m4.py", "code/evaluate_m1m4.py": E / "evaluate_m1m4.py",
 "code/run_g2f.py": E / "g2f/run_g2f.py", "code/evaluate_g2f.py": E / "g2f/evaluate_g2f.py", "code/matched_fpr_diagnostic.py": E / "g2f/diag_matched_fpr/matched_fpr.py",
 "code/group_leakage/leak_scan.py": A / "scripts/group_leakage/leak_scan.py", "code/group_leakage/blob_scan.py": A / "scripts/group_leakage/blob_scan.py",
 "code/group_leakage/blob_tokens.py": A / "scripts/group_leakage/blob_tokens.py", "code/group_leakage/regroup_folds.py": A / "scripts/group_leakage/regroup_folds.py",
 "code/group_leakage/verify_g2_links.py": E / "g2f/verify_g2_links_hashed.py",
 "code/build_preserve_minimal.py": Path(__file__),
}
for f in ["analyze_d08.py", "new_vs_d06.py", "folds_design.py", "m3m4_design.py", "final_design.py", "source_check.py", "dup_extra.py"]:
    FILES[f"code/d08_analysis/{f}"] = A / "scripts/d08_analysis" / f
for f in ["config.json", "fold_assignment.csv", "fold_counts.csv", "ws_bands.csv", "thresholds.csv", "training_log.csv", "metrics_fold.csv", "feature_importance.csv", "calibration_assignment.csv", "scores.csv"]:
    FILES[f"results/g2f_60run/run/{f}"] = E / "g2f/run" / f
for p in (E / "g2f/eval").glob("*.csv"): FILES[f"results/g2f_60run/eval/{p.name}"] = p
for f in ["summary.csv", "campaign_recall.csv", "paired_bootstrap_M1_vs_M2r.csv", "thresholds_used.csv"]:
    FILES[f"results/g2f_60run/diag_matched_fpr_DIAGNOSTIC/{f}"] = E / "g2f/diag_matched_fpr/out" / f
for f in ["config.json", "training_log.csv", "thresholds.csv", "metrics_fold.csv"]:
    FILES[f"results/m1m4_40run_G0/run/{f}"] = E / "run" / f
for p in (E / "eval").glob("*.csv"): FILES[f"results/m1m4_40run_G0/eval/{p.name}"] = p
stats = {}
n = 0
for dest, src in FILES.items():
    if src is None: continue
    d = OUT / dest; d.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    if dest.endswith(".csv"):  # per-cell sanitisation keeps CSV structure (quoted commas/newlines)
        df = pd.read_csv(src, dtype=str, keep_default_na=False)
        def clean(v):
            global n
            for rx, fn in RULES:
                v, k = rx.subn(fn, v); n += k
            return v
        df = df.map(clean); df.to_csv(d, index=False, lineterminator="\n")
    else:
        txt = src.read_text(encoding="utf-8")
        if not dest.endswith(".py"):
            for rx, fn in RULES:
                txt, k = rx.subn(fn, txt); n += k
        d.write_text(txt, encoding="utf-8")
    stats[dest] = n
(OUT / "SANITISATION_LOG.json").write_text(json.dumps({k: v for k, v in stats.items() if v}, indent=1) + "\n")
print(len(FILES) - 1, "files;", sum(stats.values()), "replacements in", sum(1 for v in stats.values() if v), "files")
