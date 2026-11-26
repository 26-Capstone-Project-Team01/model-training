"""Cross-group identical malicious-only files via git blob OIDs (ls-tree only; no content read)."""
import sys, json
import pandas as pd
S = sys.argv[1]; K = ["package", "old_version", "new_version"]
meta = json.load(open(f"{S}/d08a/in/d08_mal_meta.json")); d2k = {m["pair_dir"]: tuple(m[k] for k in K) for m in meta}
g = pd.read_csv("/home/user/d08_m1m4_experiment/inputs/malicious_pair_groups.csv", dtype=str, keep_default_na=False)
sa = pd.read_csv("/home/user/d08_m1m4_experiment/inputs/split_assignment.csv", dtype=str, keep_default_na=False)
info = g.merge(sa[K + ["split"]], on=K).set_index(K)[["splitGroup", "split"]].to_dict("index")
B = pd.read_csv(f"{S}/d08a/out4/all_blobs.tsv", sep="\t", names=["oid", "path"], dtype=str, quoting=3)
B = B[B.path.str.contains("/(?:malicious|normal)_raw/", regex=True)]
sp = B.path.str.extract(r"^(pairs/.+?)/(malicious|normal)_raw/(.*)$"); B = pd.concat([B, sp.rename(columns={0: "pair_dir", 1: "side", 2: "rel"})], axis=1)
normal_oids = set(B[B.side == "normal"].oid)
M = B[B.side == "malicious"].copy()
# per pair: changed = (rel, oid) not present in same pair's normal side
npairs = set(map(tuple, B[B.side == "normal"][["pair_dir", "rel", "oid"]].values))
has_norm = set(B[B.side == "normal"].pair_dir)
M["changed"] = [(p, r, o) not in npairs for p, r, o in M[["pair_dir", "rel", "oid"]].values]
M["key"] = M.pair_dir.map(d2k); M = M[M.key.notna() & M.key.map(lambda k: k in info)]
M["splitGroup"] = M.key.map(lambda k: info[k]["splitGroup"]); M["split"] = M.key.map(lambda k: info[k]["split"])
M["package"] = M.key.map(lambda k: k[0])
print("malicious pairs with raw dir:", M.pair_dir.nunique(), "| with normal_raw too:", len(set(M.pair_dir) & has_norm))
C = M[M.changed & ~M.oid.isin(normal_oids)]  # malicious-only content never seen in any normal_raw
C = C[~C.rel.str.endswith("package.json")]
A = C.groupby("oid").agg(ng=("splitGroup", "nunique"), npairs=("pair_dir", "nunique"), files=("rel", lambda s: ";".join(sorted({x.rsplit('/', 1)[-1] for x in s})[:4])),
     groups=("splitGroup", lambda s: ";".join(f"{k}:{v}" for k, v in s.drop_duplicates().value_counts().items())),
     gp=("pair_dir", lambda s: None), splits=("split", lambda s: ";".join(sorted(set(s))))).drop(columns="gp").reset_index()
# count pairs per group properly
pg = C.drop_duplicates(["oid", "pair_dir"]).groupby(["oid", "splitGroup"]).size().rename("n").reset_index()
A["groups"] = A.oid.map(pg.groupby("oid").apply(lambda x: ";".join(f"{a}:{b}" for a, b in sorted(zip(x.splitGroup, x.n), key=lambda t: -t[1]))))
X = A[A.ng > 1].sort_values("npairs", ascending=False)
X.to_csv(f"{S}/d08a/out4/shared_malicious_only_blobs.csv", index=False)
pd.set_option("display.width", 250); pd.set_option("display.max_colwidth", 130); pd.set_option("display.max_rows", 200)
print(len(X)); print(X.head(80).to_string(index=False))
C.to_csv(f"{S}/d08a/out4/malicious_only_changed_blobs.csv.gz", index=False)
