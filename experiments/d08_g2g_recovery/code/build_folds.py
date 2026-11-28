"""G2g step 3: recompute the 5-fold assignment for a group mapping (no model training, no Test access).

Repeats exactly the data preparation of run_g2f.py (D08 Train, clipper-6 exclusion, group_merge + row_override,
PR #13 components(), run_m1m4.greedy_folds()) and writes fold_assignment.csv in the same format.
lightgbm / sklearn are not needed by these functions; if they are not installed, empty stand-in modules are
registered only so that the two reused files can be imported (no model code is called).
Guard: --config merge_G2f.json must reproduce the stored G2f fold_assignment.csv byte for byte.
Usage: python -I -B build_folds.py --ws <d08_recovery> --config <merge json> --out <dir> [--guard <stored fold_assignment.csv>]
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, sys, types
from pathlib import Path
import pandas as pd


def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def stub_missing():
    stubbed = []
    for name in ("lightgbm", "sklearn", "sklearn.metrics", "sklearn.tree"):
        try:
            importlib.import_module(name)
        except ModuleNotFoundError:
            m = types.ModuleType(name); m.__version__ = "not-installed"
            for attr in ("average_precision_score", "precision_score", "DecisionTreeClassifier", "export_text"): setattr(m, attr, None)
            sys.modules[name] = m; stubbed.append(name)
    return stubbed


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path); m = importlib.util.module_from_spec(spec); sys.modules[name] = m
    spec.loader.exec_module(m); return m


def main():
    ap = argparse.ArgumentParser()
    for k in ("ws", "config", "out"): ap.add_argument(f"--{k}", type=Path, required=True)
    ap.add_argument("--guard", type=Path)
    a = ap.parse_args(); a.out.mkdir(parents=True, exist_ok=True)
    stubbed = stub_missing()
    R = load(a.ws / "run_m1m4.py", "run_m1m4"); snap = load(a.ws / "pr13_snapshot.py", "snap")
    assert sha(a.ws / "pr13_snapshot.py") == R.SNAPSHOT_SHA256
    T, F29 = R.load_inputs()
    ex = pd.read_csv(a.ws / "g2f/config/dev_exclusion_clipper6.csv", dtype=str, keep_default_na=False)
    exk = set(map(tuple, ex[R.KEY].values)); assert len(exk) == 6
    is_ex = T[R.KEY].apply(tuple, axis=1).isin(exk); assert is_ex.sum() == 6 and (T[is_ex].label == 1).all()
    T = T[~is_ex].copy()
    cfg = json.load(open(a.config))
    T["splitGroup_orig"] = T.splitGroup; T["splitGroup"] = T.splitGroup.replace(cfg["group_merge"])
    for o in cfg["row_override"]:
        if (o["package"], o["old_version"], o["new_version"]) in exk: continue
        m = (T.package == o["package"]) & (T.old_version == o["old_version"]) & (T.new_version == o["new_version"])
        assert m.sum() == 1 and (T[m].label == 1).all(), o; T.loc[m, "splitGroup"] = o["splitGroup"]
    T["P"] = T.apply(R.payload_key, axis=1)
    cf = T[["package", "label", "splitGroup", "largestChangedJsSha1", "changedJsSetSha1", "class"]].copy()
    cf.loc[cf.label == 0, ["splitGroup", "largestChangedJsSha1", "changedJsSetSha1"]] = ""
    T["component"] = snap.components(cf)
    T["fold"] = R.greedy_folds(T.assign(splitGroup=cf.splitGroup), snap)
    for f in range(5): snap.check_disjoint(T[T.fold != f], T[T.fold == f])
    # same sanitisation as the stored G2f file (SANITISATION_LOG.json): install-hook payload keys -> sha1[:16] tag
    T["P"] = T.P.map(lambda p: "nojs:sha1:" + hashlib.sha1(p.encode()).hexdigest()[:16] if p.startswith("nojs:") else p)
    outp = a.out / "fold_assignment.csv"
    T[R.KEY + ["row_id", "class", "era", "splitGroup_orig", "splitGroup", "component", "fold", "P"]].to_csv(outp, index=False, lineterminator="\n")
    info = {"config": str(a.config.name), "config_sha256": sha(a.config), "fold_assignment_sha256": sha(outp), "stubbed_modules": stubbed,
            "snapshot_sha256": R.SNAPSHOT_SHA256, "run_m1m4_sha256": sha(a.ws / "run_m1m4.py")}
    if a.guard: info["guard_identical"] = sha(a.guard) == info["fold_assignment_sha256"]
    (a.out / "build_info.json").write_text(json.dumps(info, indent=1) + "\n")
    print(json.dumps(info))


if __name__ == "__main__":
    main()
