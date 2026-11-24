"""X4 distribution / missingness / correlation with updateInterval (Train only, no training).
Usage: python -I -B analyze_x4.py --run run --out analysis"""
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path
import numpy as np, pandas as pd
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "d06_x1_cause_analysis"))
import common as c  # noqa: E402


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--run", type=Path, required=True); ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(); out = a.out; out.mkdir(parents=True, exist_ok=False)
    df = c.frame()
    X = pd.read_csv(a.run / "d06_x4_status.csv", keep_default_na=False)
    V = pd.read_csv(a.run / "d06_x4.csv", keep_default_na=False)
    for col in ["x4RelUpdateIntervalRatio", "x4HistoryGapCount"]:
        X[col] = pd.to_numeric(V[col].replace("", np.nan))
    for col in ["x4_interval_seconds", "x4_median_gap_seconds"]:
        X[col] = pd.to_numeric(X[col].replace("", np.nan))
    assert (X.package.values == df.package.values).all()
    X["class"], X["campaign"], X["updateInterval"] = df["class"].values, df.campaign.values, df.updateInterval.values
    X["cls_camp"] = np.where(X["class"] == "malicious", X.campaign, X["class"])
    st = pd.crosstab(X["class"], X.status, margins=True); st.to_csv(out / "status_by_class.csv", lineterminator="\n")
    camp = X.groupby("cls_camp").agg(n=("row_id", "size"), missing_ratio=("x4RelUpdateIntervalRatio", lambda s: s.isna().mean()),
                                     ratio_p10=("x4RelUpdateIntervalRatio", lambda s: s.quantile(.1)), ratio_med=("x4RelUpdateIntervalRatio", "median"),
                                     ratio_p90=("x4RelUpdateIntervalRatio", lambda s: s.quantile(.9)), ratio_gt10=("x4RelUpdateIntervalRatio", lambda s: (s > 10).mean()),
                                     gapcount_med=("x4HistoryGapCount", "median")).reset_index().sort_values("n", ascending=False)
    camp.round(4).to_csv(out / "by_class_campaign.csv", index=False, lineterminator="\n")
    rows = []
    for cls, g in X.groupby("class"):
        r = g.x4RelUpdateIntervalRatio
        rows.append({"class": cls, "n": len(g), "missing": r.isna().mean(), **{f"q{q}": r.quantile(q / 100) for q in (5, 10, 25, 50, 75, 90, 95)},
                     "gt1": (r > 1).mean(), "gt10": (r > 10).mean(), "gt100": (r > 100).mean(), "max": r.max()})
    pd.DataFrame(rows).round(4).to_csv(out / "distribution_by_class.csv", index=False, lineterminator="\n")
    ok = X[X.x4RelUpdateIntervalRatio.notna()]
    corr = {"n": len(ok), "spearman_ratio_vs_updateInterval": float(ok.x4RelUpdateIntervalRatio.corr(ok.updateInterval, method="spearman")),
            "pearson_log_ratio_vs_log_updateInterval": float(np.log1p(ok.x4RelUpdateIntervalRatio).corr(np.log1p(ok.updateInterval.clip(lower=0)))),
            "spearman_by_class": {k: float(g.x4RelUpdateIntervalRatio.corr(g.updateInterval, method="spearman")) for k, g in ok.groupby("class")},
            "numerator_vs_updateInterval": {"n": int(X.x4_interval_seconds.notna().sum()),
                                            "abs_diff_le_1s": float((np.abs(X.x4_interval_seconds - X.updateInterval) <= 1).mean()),
                                            "abs_diff_le_1h": float((np.abs(X.x4_interval_seconds - X.updateInterval) <= 3600).mean()),
                                            "spearman": float(X.x4_interval_seconds.corr(X.updateInterval, method="spearman"))},
            "spearman_gapcount_vs_updateInterval": float(X.x4HistoryGapCount.corr(X.updateInterval, method="spearman"))}
    (out / "correlation.json").write_text(json.dumps(corr, indent=1) + "\n")
    # single-feature separation (threshold-free) on rows with value, malicious vs non-malicious, and HB vs malicious
    from sklearn.metrics import roc_auc_score
    auc = {}
    for name, sub in [("all", ok), ("hard_benign_vs_malicious", ok[ok["class"] != "benign"])]:
        y = (sub["class"] == "malicious").astype(int)
        auc[name] = {"x4RelUpdateIntervalRatio": float(roc_auc_score(y, sub.x4RelUpdateIntervalRatio)), "updateInterval": float(roc_auc_score(y, sub.updateInterval))}
    (out / "single_feature_auc.json").write_text(json.dumps(auc, indent=1) + "\n")
    man = {"script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
           "inputs": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [a.run / "d06_x4.csv", a.run / "d06_x4_status.csv"]},
           "outputs": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.glob("*")) if p.is_file()}}
    (out / "manifest.json").write_text(json.dumps(man, indent=1) + "\n")
    print(st.to_string()); print(pd.DataFrame(rows).round(3).to_string(index=False)); print(json.dumps(corr, indent=1)); print(json.dumps(auc, indent=1))
    print(camp.round(3).to_string(index=False))


if __name__ == "__main__":
    main()
