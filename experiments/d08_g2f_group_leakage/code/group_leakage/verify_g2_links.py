"""Verify G2: same-attack evidence links must not cross folds (Train). Read-only, metadata/hash level."""
import sys, json
import pandas as pd
S, FA = sys.argv[1:3]
K = ["package", "old_version", "new_version"]
meta = {m["pair_dir"]: tuple(m[k] for k in K) for m in json.load(open(f"{S}/d08a/in/d08_mal_meta.json"))}
fa = pd.read_csv(FA, dtype=str, keep_default_na=False); fa = fa[fa["class"] == "malicious"]
idx = {tuple(r[k] for k in K): r for r in fa.to_dict("records")}
g = pd.read_csv("/home/user/d08_m1m4_experiment/inputs/malicious_pair_groups.csv", dtype=str, keep_default_na=False)
links = []  # (tier, evidence, key_a, key_b)
def link_set(keys, tier, ev):
    keys = [k for k in dict.fromkeys(keys) if k in idx]
    for k in keys[1:]: links.append((tier, ev, keys[0], k))
# A1: identical malicious-only changed file (blob oid), excluding vendored dependency trees
C = pd.read_csv(f"{S}/d08a/out4/malicious_only_changed_blobs.csv.gz", dtype=str, keep_default_na=False)
C = C[~C.rel.str.contains(r"\.pnpm-store/|node_modules/", regex=True)]
C["key"] = C.pair_dir.map(meta)
for o, s in C.groupby("oid"):
    if s.pair_dir.nunique() > 1: link_set(list(s.key), "A", "identical_malicious_file:" + s.rel.iloc[0].rsplit("/", 1)[-1])
# A2: identical decoded inner payload / identical specific IOC
R = pd.read_csv(f"{S}/d08a/out4/rotpacker_decoded_map.csv", dtype=str); R["key"] = R.pair_dir.map(meta)
for h, s in R.groupby("p_sha1"): link_set(list(s.key), "A", "identical_decrypted_payload")
BT = pd.read_csv(f"{S}/d08a/out4/blob_tokens.csv.gz", dtype=str, keep_default_na=False); BT["key"] = BT.pair_dir.map(meta)
link_set(list(BT[BT.token == "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af"].key), "A", "qix_wallet")
gk = g.assign(key=list(map(tuple, g[K].values)))
import hashlib  # toptal webhook token kept only as sha1[:16] (capability URL not stored)
link_set(list(gk[gk.addedInstallHooks.map(lambda s: any(hashlib.sha1(u.encode()).hexdigest()[:16] == "0c7553fed3f1e6aa" for u in __import__("re").findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", s)))].key), "A", "toptal_webhook_token")
# B: shared attacker-authored code family (npmoidc markers, ROT/AES loader)
F = pd.read_csv(f"{S}/d08a/out4/family_marker_hits.csv", dtype=str, keep_default_na=False); F["key"] = F.pair.map(meta)
link_set(list(F[F.mark.isin(["npmoidc", "audience", "format-check", "ghrunner", "stillsuit", "rotpacker"])].key) + list(R.key), "B", "npmoidc_family_code")
# C: shared loader template only (bun 1.3.13 setup.mjs)
link_set(list(F[F.mark == "bun1313"].key), "C", "bun1313_loader_template")
L = pd.DataFrame(links, columns=["tier", "evidence", "a", "b"])
L["fold_a"] = L.a.map(lambda k: idx[k]["fold"]); L["fold_b"] = L.b.map(lambda k: idx[k]["fold"])
L["grp_a"] = L.a.map(lambda k: idx[k]["splitGroup_exp"]); L["grp_b"] = L.b.map(lambda k: idx[k]["splitGroup_exp"])
X = L[L.fold_a != L.fold_b]
out = X.groupby(["tier", "evidence", "grp_a", "fold_a", "grp_b", "fold_b"]).size().rename("links").reset_index()
pd.set_option("display.width", 250); pd.set_option("display.max_colwidth", 70)
print("total links", len(L), "| cross-fold links", len(X)); print(L.groupby("tier").size().to_string())
print(out.to_string(index=False))
# per tier: connected components & fold span
for tiers in (["A"], ["A", "B"], ["A", "B", "C"]):
    par = {}
    def f(x):
        par.setdefault(x, x)
        while par[x] != x: par[x] = par[par[x]]; x = par[x]
        return x
    for r in L[L.tier.isin(tiers)].itertuples(): par[f(r.a)] = f(r.b)
    comp = pd.Series({k: f(k) for k in par})
    span = comp.groupby(comp).apply(lambda s: sorted({idx[k]["fold"] for k in s.index}))
    multi = span[span.map(len) > 1]
    print(f"tiers {tiers}: clusters {comp.nunique()}, spanning >1 fold: {len(multi)}",
          [(len(comp[comp == c]), v, sorted({idx[k]['splitGroup_exp'] for k in comp[comp == c].index})) for c, v in multi.items()])
L.to_csv(f"{S}/d08a/out6_links_{FA.split('/')[-2]}.csv", index=False)
