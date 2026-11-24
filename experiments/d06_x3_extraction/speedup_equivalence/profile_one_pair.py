import sys, time, tarfile, io, json, tempfile
from pathlib import Path
from datetime import datetime, timezone
sys.path.insert(0, '/home/user/da-x3/src')
from depbee_analyzer.core.models import PackageVersionSnapshot
from depbee_analyzer.core import loader
from depbee_analyzer.core.pipeline import resolve_extractors
from depbee_analyzer.core.source_files import collect_source_files
from depbee_analyzer.extractors import x3_context as x3, code_context as cc
pkg, old, new = sys.argv[1:4]
snaps = {}
tmp = Path(tempfile.mkdtemp())
for side, v in (("old", old), ("new", new)):
    data = Path(f"/home/user/d06_train_x3_work/cache/{pkg.replace('/', '__')}@{v}.tgz").read_bytes()
    d = tmp / side
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        t.extractall(d, filter="data")
    root = loader._locate_package_root(d, pkg, v)
    snaps[side] = PackageVersionSnapshot(pkg, v, datetime(1970, 1, 1, tzinfo=timezone.utc), json.loads((root / "package.json").read_text()), root)
for ex in resolve_extractors(("package_json", "obfuscation", "code_context", "x3_context", "dependency_change")):
    t0 = time.time(); ex.extract(snaps["old"], snaps["new"]); print(ex.name, round(time.time() - t0, 1), flush=True)
o, n = collect_source_files(snaps["old"]), collect_source_files(snaps["new"])
t0 = time.time(); x3.changed_token_counts(o, n); print("  x3 tokens only", round(time.time() - t0, 1))
t0 = time.time(); cc.added_call_features(o, n, (old, new)); print("  added_call_features only", round(time.time() - t0, 1))
