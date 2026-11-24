"""X4: relative update anomaly from the registry packument `time` map (definition fixed before extraction).

Inputs per pair: the package's packument `time` map (version -> ISO publish time), old_version, new_version.
No manifest, tarball or package code is used, so deleted malicious versions (whose manifests are gone) are treated the
same as other versions as long as their `time` entry exists.

Cleaning
  - drop the keys "created" and "modified"
  - drop npm security placeholder versions (a version string ending in "-security", e.g. 0.0.1-security): they are
    published by npm after removal and are not part of the maintainer's release history
History (only information up to the old version's publish time)
  - T_old = time[old_version], T_new = time[new_version]
  - H = all cleaned publish times t <= T_old (includes T_old itself), sorted
  - gaps = consecutive differences of the last 11 times of H (at most 10 gaps, the most recent ones)
Features (model inputs)
  - x4HistoryGapCount        = len(gaps) (0..10)
  - x4RelUpdateIntervalRatio = (T_new - T_old) / max(median(gaps), 60 s)
                               NaN when x4HistoryGapCount < 2 ("history too short": old is the 1st or 2nd release)
The 60-second floor keeps bursts of near-simultaneous releases (monorepo publish) from dividing by ~0.
Status (not a feature): ok | history_short | registry_<status> | old_missing | new_missing | new_before_old.
For every status other than ok/history_short both features are NaN; history_short keeps x4HistoryGapCount.
"""
from __future__ import annotations

from datetime import datetime
import math
import statistics

MAX_GAPS = 10
MIN_GAPS = 2
FLOOR_SECONDS = 60.0
FEATURES = ("x4RelUpdateIntervalRatio", "x4HistoryGapCount")


def _iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def clean_time_map(time_map: dict | None) -> dict[str, datetime]:
    out = {}
    for k, v in (time_map or {}).items():
        if k in ("created", "modified") or k.endswith("-security") or not isinstance(v, str):
            continue
        try:
            out[k] = _iso(v)
        except ValueError:
            continue
    return out


def x4_features(time_map: dict | None, old_version: str, new_version: str) -> dict:
    nan = {"x4RelUpdateIntervalRatio": math.nan, "x4HistoryGapCount": math.nan}
    tm = clean_time_map(time_map)
    if old_version not in tm:
        return nan | {"status": "old_missing"}
    if new_version not in tm:
        return nan | {"status": "new_missing"}
    t_old, t_new = tm[old_version], tm[new_version]
    if t_new < t_old:
        return nan | {"status": "new_before_old"}
    history = sorted(t for t in tm.values() if t <= t_old)[-(MAX_GAPS + 1):]
    gaps = [(b - a).total_seconds() for a, b in zip(history, history[1:])]
    out = {"x4HistoryGapCount": float(len(gaps)), "x4_interval_seconds": (t_new - t_old).total_seconds(),
           "x4_median_gap_seconds": statistics.median(gaps) if gaps else math.nan}
    if len(gaps) < MIN_GAPS:
        return out | {"x4RelUpdateIntervalRatio": math.nan, "status": "history_short"}
    return out | {"x4RelUpdateIntervalRatio": out["x4_interval_seconds"] / max(out["x4_median_gap_seconds"], FLOOR_SECONDS), "status": "ok"}
