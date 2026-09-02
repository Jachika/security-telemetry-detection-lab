from __future__ import annotations
import argparse, json
from pathlib import Path
from .generate import generate_events
from .normalize import normalize_event
from .detect import detect
from .evaluate import classification_metrics, false_positive_reduction
from .report import write_summary, plot_metrics

def _write_jsonl(path: Path, rows):
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")

def benchmark(events: int, seed: int, out: str):
    outdir = Path(out)
    outdir.mkdir(parents=True, exist_ok=True)

    raw = [e.to_dict() for e in generate_events(events, seed)]
    normalized = [normalize_event(e) for e in raw]

    baseline_alerts = [a for e in normalized for a in detect(e, tuned=False)]
    tuned_alerts = [a for e in normalized for a in detect(e, tuned=True)]

    baseline_ids = {a["event_id"] for a in baseline_alerts}
    tuned_ids = {a["event_id"] for a in tuned_alerts}
    baseline_m = classification_metrics(normalized, baseline_ids)
    tuned_m = classification_metrics(normalized, tuned_ids)

    metrics = {
        "events_processed": len(normalized),
        "seed": seed,
        "baseline": baseline_m,
        "tuned": tuned_m,
        "false_positive_reduction": false_positive_reduction(baseline_m, tuned_m)
    }

    _write_jsonl(outdir / "raw_events.jsonl", raw)
    _write_jsonl(outdir / "normalized_events.jsonl", normalized)
    _write_jsonl(outdir / "alerts.jsonl", tuned_alerts)
    (outdir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    write_summary(metrics, outdir)
    plot_metrics(metrics, outdir)
    print(json.dumps(metrics, indent=2))

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("benchmark")
    b.add_argument("--events", type=int, default=120_000)
    b.add_argument("--seed", type=int, default=42)
    b.add_argument("--out", default="artifacts")
    args = parser.parse_args()

    if args.cmd == "benchmark":
        benchmark(args.events, args.seed, args.out)

if __name__ == "__main__":
    main()
