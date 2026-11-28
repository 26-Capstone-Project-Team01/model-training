#!/usr/bin/env bash
# Reproduce the G2g group recovery (static text analysis only; no training, no Test evaluation, no package code execution).
# WS   = recovery workspace laid out as in README.md section 4 (run_m1m4.py, pr13_snapshot.py, inputs/, g2f/config, g2f/run)
# DATA = npm-malware-package-pairs checkout whose pairs/ tree equals D08 2c48bd83
# OUT  = new output directory
set -euo pipefail
WS=${1:?workspace}; DATA=${2:?data checkout}; OUT=${3:?output dir}
C=$(cd "$(dirname "$0")/code" && pwd)
mkdir -p "$OUT"
python3 -I -B "$C/build_folds.py" --ws "$WS" --config "$WS/g2f/config/merge_G2f.json" --out "$OUT/folds_G2f_guard" --guard "$WS/g2f/run/fold_assignment.csv"
python3 -I -B "$C/scan_pairs.py" --data "$DATA" --ws "$WS" --out "$OUT/scan" --workers 4
python3 -I -B "$C/scan_hidden_raw.py" --scan "$OUT/scan" --data "$DATA" --out "$OUT/hidden_raw" --workers 4
python3 -I -B "$C/decide_families.py" --scan "$OUT/scan" --hidden "$OUT/hidden_raw" --out "$OUT/evidence"
python3 -I -B "$C/make_g2g.py" --ws "$WS" --members "$OUT/evidence/family_membership.csv" --out "$OUT/mapping"
python3 -I -B "$C/build_folds.py" --ws "$WS" --config "$OUT/mapping/merge_G2g.json" --out "$OUT/folds_G2g"
python3 -I -B "$C/compare_g2f_g2g.py" --ws "$WS" --g2f "$WS/g2f/run/fold_assignment.csv" --g2g "$OUT/folds_G2g/fold_assignment.csv" \
  --members "$OUT/evidence/family_membership.csv" --out "$OUT/compare"
