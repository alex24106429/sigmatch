"""Build a trimmed SigmaHQ rule tree containing only Sysmon-applicable rules.

sigmatch evaluates Sigma rules directly against Microsoft-Windows-Sysmon
events.  The full SigmaHQ repository is much larger than that: it also carries
Linux/macOS/cloud rules, Windows Security/System/PowerShell/Defender rules and
categories that have no Sysmon event-id mapping.  Those can never match, yet
they still cost parse/compile time on every load.

This script uses sigmatch's own loader as the source of truth, so the output
contains exactly the files that ``load_rules()`` turns into at least one
compiled rule.  Original relative paths are preserved, and the result is a
drop-in Sigma repository root (``<out>/rules`` plus the optional extended
collections).

Usage:
    python tools/build_sysmon_ruleset.py \
        --sigma-root C:/Users/Administrator/sigma \
        --out Z:/projects/sigmatch/sigma

Re-run it after updating the SigmaHQ checkout; ``--out`` is rebuilt from
scratch (stale files are removed).
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

# Make the script runnable from a source checkout without installation.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sigmatch.rules import (  # noqa: E402
    LoadResult,
    _event_ids_for_rule,
    _iter_rule_files,
    _iter_yaml_documents,
    expand_rule_paths,
    load_rules,
)

COLLECTIONS = (
    "rules",
    "rules-emerging-threats",
    "rules-threat-hunting",
    "rules-compliance",
    "rules-dfir",
)


def _skip_reason(path: Path) -> str:
    """Best-effort reason why a file produced no sysmon-applicable rule."""

    try:
        documents = list(_iter_yaml_documents(path))
    except Exception as exc:  # malformed YAML
        return f"unreadable:{type(exc).__name__}"
    if not documents:
        return "no_detection"
    reasons: list[str] = []
    for document in documents:
        logsource = document.get("logsource")
        detection = document.get("detection")
        if not isinstance(logsource, Mapping):
            reasons.append("missing_logsource")
            continue
        if not isinstance(detection, Mapping):
            reasons.append("missing_detection")
            continue
        _, reason = _event_ids_for_rule(logsource, detection)
        if reason.startswith("loaded:"):
            # Applicable per logsource, so the rejection happened later
            # (compile error or duplicate id).
            return "compile_error_or_duplicate"
        reasons.append(reason)
    # Prefer the first non-generic reason for readability.
    return reasons[0] if reasons else "unknown"


def _collection_of(relative: Path) -> str:
    return relative.parts[0] if len(relative.parts) > 1 else "."


def build(sigma_root: Path, out_dir: Path, collections: Sequence[str]) -> dict[str, Any]:
    sigma_root = sigma_root.resolve()
    if not sigma_root.is_dir():
        raise SystemExit(f"Sigma repository not found: {sigma_root}")

    selected = [sigma_root / name for name in collections if (sigma_root / name).is_dir()]
    if not selected:
        raise SystemExit(f"No rule collections found under {sigma_root}")

    # Loading the repo root with --all-rule-sets mirrors exactly what sigmatch
    # does at runtime; the resulting rule.path set tells us which files matter.
    expanded = expand_rule_paths(selected, all_rule_sets=False)
    result: LoadResult = load_rules(expanded)
    keep = {Path(rule.path).resolve() for rule in result.rules}
    if not keep:
        raise SystemExit("No Sysmon-applicable rules were found; refusing to write an empty set")

    all_files = set()
    for path in expanded:
        all_files.update(p.resolve() for p in _iter_rule_files([path]))

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    kept_by_collection: Counter[str] = Counter()
    skipped_by_collection: Counter[str] = Counter()
    skipped_by_reason: Counter[str] = Counter()
    skipped_examples: dict[str, list[str]] = {}

    for source in sorted(all_files):
        try:
            relative = source.relative_to(sigma_root)
        except ValueError:
            relative = Path(source.name)
        collection = _collection_of(relative)
        if source in keep:
            destination = out_dir / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            kept_by_collection[collection] += 1
        else:
            reason = _skip_reason(source)
            skipped_by_collection[collection] += 1
            skipped_by_reason[reason] += 1
            examples = skipped_examples.setdefault(reason, [])
            if len(examples) < 5:
                examples.append(relative.as_posix())

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sigma_root": str(sigma_root),
        "collections": list(selected_names(selected, sigma_root)),
        "files_scanned": len(all_files),
        "files_kept": len(keep),
        "rules_compiled": len(result.rules),
        "load_errors": len(result.errors),
        "kept_by_collection": dict(sorted(kept_by_collection.items())),
        "skipped_by_collection": dict(sorted(skipped_by_collection.items())),
        "skipped_by_reason": dict(skipped_by_reason.most_common()),
        "skipped_examples": skipped_examples,
        "event_id_counts": {str(k): v for k, v in sorted(result.event_id_counts.items())},
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def selected_names(selected: Sequence[Path], sigma_root: Path) -> list[str]:
    return [path.relative_to(sigma_root).as_posix() for path in selected]

def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--sigma-root",
        default=str(Path.home() / "sigma"),
        help="Full SigmaHQ repository checkout (default: ~/sigma)",
    )
    parser.add_argument(
        "--out",
        default=str(Path(__file__).resolve().parent.parent / "sigma"),
        help="Output directory (default: <sigmatch>/sigma)",
    )
    parser.add_argument(
        "--collections",
        nargs="+",
        default=list(COLLECTIONS),
        help="Top-level rule collections to filter (default: all five)",
    )
    args = parser.parse_args(argv)

    manifest = build(Path(args.sigma_root), Path(args.out), args.collections)
    print(f"wrote {manifest['files_kept']} files "
          f"({manifest['rules_compiled']} rules) to {Path(args.out).resolve()}")
    for name, count in manifest["kept_by_collection"].items():
        print(f"  {name:28s} {count}")
    print("skipped by reason:")
    for reason, count in manifest["skipped_by_reason"].items():
        print(f"  {reason:55s} {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
