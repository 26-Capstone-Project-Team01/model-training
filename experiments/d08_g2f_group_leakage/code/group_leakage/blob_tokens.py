"""IOC tokens from malicious-only changed files (blob content read as bytes; nothing executed)."""
import sys, re, subprocess
import pandas as pd
S, REPO = sys.argv[1:3]
K = pd.read_csv(f"{S}/d08a/out4/scan_blobs.csv.gz", dtype=str, keep_default_na=False)
PAT = {k: re.compile(v) for k, v in {
 "url": rb"https?://[A-Za-z0-9._~:/?#@!$&%+=-]{6,200}", "ip": rb"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b",
 "uuid": rb"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "eth": rb"\b0x[0-9a-fA-F]{40}\b",
 "btc": rb"\b(?:bc1[0-9a-z]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", "tg_token": rb"\b\d{8,10}:[A-Za-z0-9_-]{35}\b",
 "marker": rb"(?i)(?:shai-?hulud|sha1-hulud|s1ngularity|webhook\.site|ngrok|pipedream|oast|burpcollaborator|interact\.sh|discord(?:app)?\.com/api/webhooks/[0-9]+)"}.items()}
p = subprocess.Popen(["git", "-c", "gc.auto=0", "cat-file", "--batch"], cwd=REPO, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env={"GIT_NO_LAZY_FETCH": "1", "PATH": "/usr/bin:/bin"})
rows = []; miss = 0
for oid in K.oid.drop_duplicates():
    p.stdin.write((oid + "\n").encode()); p.stdin.flush()
    h = p.stdout.readline().split()
    if h[1] == b"missing": miss += 1; continue
    n = int(h[2]); d = p.stdout.read(n); p.stdout.read(1)
    d = d[:50_000_000]
    for k, rx in PAT.items():
        for t in set(rx.findall(d)): rows.append((oid, k, t.decode("latin1")))
TK = pd.DataFrame(rows, columns=["oid", "kind", "token"])
M = TK.merge(K[["oid", "pair_dir", "rel", "splitGroup", "split", "package"]], on="oid")
M.to_csv(f"{S}/d08a/out4/blob_tokens.csv.gz", index=False)
print("missing", miss, "token rows", len(M), "pairs with tokens", M.pair_dir.nunique())
