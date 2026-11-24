"""Unit tests for x4.py (synthetic time maps only). Run: python -I -B test_x4.py"""
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from x4 import x4_features  # noqa: E402

DAY = 86400.0


def t(day, sec=0):
    return f"2024-01-{day:02d}T00:00:{sec:02d}.000Z"


def test_basic_ratio_uses_only_history_up_to_old():
    tm = {"created": t(1), "modified": t(30), "1.0.0": t(1), "1.0.1": t(3), "1.0.2": t(5), "1.0.3": t(7), "1.0.4": t(27), "2.0.0": t(28)}
    r = x4_features(tm, "1.0.3", "1.0.4")
    assert r["status"] == "ok" and r["x4HistoryGapCount"] == 3
    assert r["x4RelUpdateIntervalRatio"] == 20 * DAY / (2 * DAY)  # later releases (2.0.0) are not used


def test_history_short_is_nan_but_keeps_gap_count():
    r = x4_features({"1.0.0": t(1), "1.0.1": t(2), "1.0.2": t(9)}, "1.0.1", "1.0.2")
    assert r["status"] == "history_short" and r["x4HistoryGapCount"] == 1 and math.isnan(r["x4RelUpdateIntervalRatio"])
    r = x4_features({"1.0.0": t(1), "1.0.1": t(9)}, "1.0.0", "1.0.1")
    assert r["x4HistoryGapCount"] == 0 and math.isnan(r["x4RelUpdateIntervalRatio"])


def test_security_placeholder_and_meta_keys_ignored():
    tm = {"0.0.1-security": t(2), "1.0.0": t(1), "1.0.1": t(3), "1.0.2": t(5), "1.0.3": t(15)}
    r = x4_features(tm, "1.0.2", "1.0.3")
    assert r["x4HistoryGapCount"] == 2 and r["x4RelUpdateIntervalRatio"] == 10 * DAY / (2 * DAY)


def test_floor_for_burst_releases():
    tm = {"1.0.0": t(1, 0), "1.0.1": t(1, 1), "1.0.2": t(1, 2), "1.0.3": t(2)}
    r = x4_features(tm, "1.0.2", "1.0.3")
    assert r["x4RelUpdateIntervalRatio"] == (DAY - 2) / 60.0


def test_at_most_ten_recent_gaps():
    tm = {f"1.0.{i}": t(1 + i) for i in range(20)}
    tm["1.0.20"] = t(31)
    r = x4_features(tm, "1.0.19", "1.0.20")
    assert r["x4HistoryGapCount"] == 10 and r["x4RelUpdateIntervalRatio"] == 11.0


def test_missing_versions_and_order():
    tm = {"1.0.0": t(1), "1.0.1": t(2), "1.0.2": t(3)}
    assert x4_features(tm, "0.9.0", "1.0.2")["status"] == "old_missing"
    assert x4_features(tm, "1.0.1", "9.9.9")["status"] == "new_missing"
    assert x4_features(None, "1.0.1", "1.0.2")["status"] == "old_missing"
    tm2 = {"1.0.0": t(1), "1.0.1": t(2), "1.0.2": t(3), "1.1.0": t(4), "1.0.3": t(5)}
    r = x4_features(tm2, "1.1.0", "1.0.2")
    assert r["status"] == "new_before_old" and math.isnan(r["x4HistoryGapCount"])


if __name__ == "__main__":
    n = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            n += 1
    print(f"{n} tests passed")
