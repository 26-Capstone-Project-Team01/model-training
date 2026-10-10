"""Campaign-aware K-fold cross-validation fold assignment over Train+Validation only.

Builds connected components the same way train_model.py's assign_components() does for the
Train/Validation split (package <-> malicious splitGroup union-find, generic-bucket splitGroups
like individuals_case excluded from the union so unrelated single-package compromises stay
independent), then packs those components into K folds in two phases: malicious-bearing
components first (largest-first, least-loaded-fold / LPT, balanced against the malicious total
only), then every remaining benign/hard_benign-only component by simple round-robin. See
assign_folds()'s docstring for why these have to be two separate phases.

Because component membership is derived from `package.map(uf.find)`, two rows sharing the same
package string always land in the same component regardless of class -- this is what also keeps
same-package benign/hard_benign rows from being split across folds, with no extra logic needed.

Test.csv is never read here and is not affected by this script.

Usage (from the repo root):
    python scripts/make_cv_folds.py --k 5 --output splits/cv_5fold_assignment.csv
    python scripts/make_cv_folds.py --k 3 --output splits/cv_3fold_assignment.csv
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Dict

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DATA_DIR = BASE_DIR / "data" / "raw"
TRAIN_PATH = RAW_DATA_DIR / "train.csv"
UPSTREAM_SPLIT_ASSIGNMENT_PATH = RAW_DATA_DIR / "split_assignment.csv"

ID_COLS = ["package", "old_version", "new_version"]
CLASSES = ["malicious", "benign", "hard_benign"]

# Same pattern as train_model.py's GENERIC_BUCKET_SPLIT_GROUP: these splitGroup values are
# placeholders for "unrelated single-package compromises", not a real shared campaign.
GENERIC_BUCKET_SPLIT_GROUP = re.compile(r"^(individual-compromise(-\d+(?:st|nd|rd|th))?|individuals_case)$")


def is_shared_attack_split_group(split_group) -> bool:
    return bool(split_group) and not GENERIC_BUCKET_SPLIT_GROUP.match(split_group)


class UnionFind:
    """Disjoint-set over arbitrary hashable node labels, with path compression."""

    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def load_pool() -> pd.DataFrame:
    """Train+Validation pool only (2,767 rows) -- test.csv is never read here."""
    train_df = pd.read_csv(TRAIN_PATH)
    upstream = pd.read_csv(UPSTREAM_SPLIT_ASSIGNMENT_PATH)
    merged = train_df[ID_COLS].merge(upstream[ID_COLS + ["class", "splitGroup"]], on=ID_COLS, how="left")
    missing = merged[merged["class"].isna()]
    if not missing.empty:
        raise ValueError(f"{UPSTREAM_SPLIT_ASSIGNMENT_PATH}에서 매칭되지 않은 pair가 있습니다:\n{missing[ID_COLS]}")
    return merged


def assign_components(merged: pd.DataFrame) -> pd.Series:
    """Union package with its malicious splitGroup (generic buckets excluded) -- identical
    construction to train_model.py's assign_components(), reused here for CV folds."""
    uf = UnionFind()
    for _, row in merged.iterrows():
        pkg_node = f"pkg:{row['package']}"
        if row["class"] == "malicious" and pd.notna(row["splitGroup"]) and is_shared_attack_split_group(row["splitGroup"]):
            uf.union(pkg_node, f"grp:{row['splitGroup']}")
    return merged["package"].map(lambda pkg: uf.find(f"pkg:{pkg}"))


def assign_folds(merged: pd.DataFrame, k: int) -> Dict[str, int]:
    """Two-phase fold assignment.

    Phase 1 places every component that contains at least one malicious row, balancing *only*
    the malicious count against its k-way target. Only malicious has a real grouping constraint
    (same package, or same real campaign); benign/hard_benign rows that happen to ride along in
    one of these components (sharing a package name with a malicious row) go wherever that
    component goes, as a side effect of sharing a package -- not something this phase optimizes
    for.

    Phase 1 must not also chase benign/hard_benign balance: summing deviations across all three
    classes in one cost (an earlier version of this function did that) makes an empty fold look
    permanently "expensive" the moment any other fold picks up a large malicious campaign, since
    the empty fold's malicious deficit alone can outweigh another fold's malicious surplus --
    benign/hard_benign rows then pile onto the folds that already "won" malicious components,
    starving some folds of data entirely. Verified against this exact failure (k=5 collapsing to
    3 used folds, k=3 to 2) before switching to two phases.

    Within phase 1 itself, components are placed on the *currently least-loaded* fold (classic
    LPT / multiprocessor-scheduling heuristic) rather than the fold "closest to target": closest-
    to-target has the same rich-get-richer failure mode once a few large campaigns each claim one
    fold near its target share -- every later, smaller component then still prefers those
    near-target folds (small deviation) over the untouched folds (whose deficit never shrinks
    because nothing is ever placed there), so the untouched folds stay empty. LPT has no such
    trap: the least-loaded fold is always eligible and strictly gains ground each round.

    Phase 2 handles every remaining component (no malicious row at all -- in practice almost
    always a single benign/hard_benign row, since only 2 benign rows in the whole pool happen to
    share a package name with another benign row and nothing else). These are assigned by a
    simple deterministic round-robin per class, independent of what phase 1 did.
    """
    comp_counts = merged.groupby(["component", "class"]).size().unstack(fill_value=0)
    for cls in CLASSES:
        if cls not in comp_counts.columns:
            comp_counts[cls] = 0
    comp_to_fold: Dict[str, int] = {}

    # Phase 1: malicious-bearing components, largest first, each to the least-loaded fold (LPT).
    fold_mal_count = [0] * k
    mal_components = comp_counts.index[comp_counts["malicious"] > 0]
    ordered = sorted(mal_components, key=lambda c: (-comp_counts.loc[c, "malicious"], c))
    for comp in ordered:
        size = comp_counts.loc[comp, "malicious"]
        best_fold = min(range(k), key=lambda f: (fold_mal_count[f], f))
        comp_to_fold[comp] = best_fold
        fold_mal_count[best_fold] += size

    # Phase 2: remaining components (no malicious row), round-robin per class independently.
    remaining = comp_counts.index[~comp_counts.index.isin(comp_to_fold)]
    for cls in CLASSES:
        if cls == "malicious":
            continue
        cls_components = sorted((c for c in remaining if comp_counts.loc[c, cls] > 0))
        for i, comp in enumerate(cls_components):
            comp_to_fold[comp] = i % k

    return comp_to_fold


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--k", type=int, required=True, help="fold 수 (예: 3 또는 5)")
    parser.add_argument("--output", required=True, help="fold 배정 결과를 쓸 csv 경로")
    args = parser.parse_args()

    merged = load_pool()
    merged["component"] = assign_components(merged)
    comp_to_fold = assign_folds(merged, args.k)
    merged["fold"] = merged["component"].map(comp_to_fold)
    merged["assignedBy"] = merged["component"].map(merged.groupby("component").size() > 1).map(
        {True: "connectedComponent", False: "greedyFill"}
    )

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    merged.drop(columns="component").to_csv(out_path, index=False)
    print(f"{args.k}-fold 배정을 {out_path}에 저장했습니다. (총 {len(merged)}행)")


if __name__ == "__main__":
    main()
