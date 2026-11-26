"""Cross-splitGroup shared-signature scan (read-only, metadata only; no models)."""
import sys, json, re
import pandas as pd
GR, META, OUT = sys.argv[1:4]
K = ["package", "old_version", "new_version"]
g = pd.read_csv(GR, dtype=str, keep_default_na=False)
m = pd.DataFrame(json.load(open(META)))[K + ["split", "collection_round", "diff_fingerprint_sha256", "malicious_source"]]
m["src"] = m.malicious_source.map(lambda d: d.get("type", "") if isinstance(d, dict) else "")
T = g.merge(m.drop(columns="malicious_source"), on=K, how="left")
print("unmatched meta:", T.split.isna().sum(), "| split counts", T.split.value_counts().to_dict())
URL = re.compile(r"(https?://[^\s'\";|&)]+|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b)")
rows = []
def add(kind, val, r): rows.append({"kind": kind, "value": val, "splitGroup": r.splitGroup, "split": r.split, "package": r.package, "new_version": r.new_version, "src": r.src})
for r in T.itertuples():
    if r.largestChangedJsSha1: add("largestChangedJsSha1", r.largestChangedJsSha1, r)
    if r.changedJsSetSha1: add("changedJsSetSha1", r.changedJsSetSha1, r)
    if r.diff_fingerprint_sha256: add("diff_fingerprint", r.diff_fingerprint_sha256, r)
    if r.addedInstallHooks: add("hook_full", r.addedInstallHooks, r)
    for tok in set(URL.findall(r.addedInstallHooks)): add("hook_url_ip_uuid", tok, r)
    for d in filter(None, r.addedDependencies.split(";")): add("dep", d, r)
    add("pkg_new", r.package + "@" + r.new_version, r)
L = pd.DataFrame(rows)
agg = L.groupby(["kind", "value"]).agg(n_groups=("splitGroup", "nunique"), n_rows=("splitGroup", "size"),
        groups=("splitGroup", lambda s: ";".join(f"{k}:{v}" for k, v in s.value_counts().items())),
        splits=("split", lambda s: ";".join(sorted(set(s)))), n_pkg=("package", "nunique")).reset_index()
X = agg[agg.n_groups > 1].sort_values(["kind", "n_rows"], ascending=[True, False])
X.to_csv(f"{OUT}/cross_group_shared_signatures.csv", index=False)
pd.set_option("display.width", 260); pd.set_option("display.max_colwidth", 140)
for k, s in X.groupby("kind"): print("\n==", k, len(s)); print(s[["value", "n_groups", "n_rows", "n_pkg", "splits", "groups"]].head(40).to_string(index=False))
# group overview
ov = T.groupby("splitGroup").agg(rows=("package", "size"), train=("split", lambda s: (s == "train").sum()), test=("split", lambda s: (s == "test").sum()),
        pkgs=("package", "nunique"), srcs=("src", lambda s: ";".join(sorted(set(s)))), rounds=("collection_round", lambda s: ";".join(sorted(set(s)))),
        nojs=("largestChangedJsSha1", lambda s: (s == "").sum()))
ov.to_csv(f"{OUT}/group_overview.csv"); print(ov.to_string())
