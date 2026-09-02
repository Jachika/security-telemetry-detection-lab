from __future__ import annotations
import json
from pathlib import Path

def write_summary(metrics: dict, outdir: Path):
    b = metrics["baseline"]
    t = metrics["tuned"]
    reduction_pct = metrics["false_positive_reduction"] * 100.0
    text = f"""# Detection Benchmark Results

- Events processed: **{metrics['events_processed']:,}**
- Baseline precision: **{b['precision']:.3f}**
- Baseline recall: **{b['recall']:.3f}**
- Baseline false positives: **{b['fp']:,}**
- Tuned precision: **{t['precision']:.3f}**
- Tuned recall: **{t['recall']:.3f}**
- Tuned false positives: **{t['fp']:,}**
- False-positive reduction: **{reduction_pct:.1f}%**
- Recall change: **{(t['recall'] - b['recall']) * 100:+.1f} points**

"""
    (outdir / "summary.md").write_text(text, encoding="utf-8")

def plot_metrics(metrics: dict, outdir: Path):
    import matplotlib.pyplot as plt

    labels = ["Baseline", "Tuned"]
    precision = [metrics["baseline"]["precision"], metrics["tuned"]["precision"]]
    recall = [metrics["baseline"]["recall"], metrics["tuned"]["recall"]]
    fpr = [metrics["baseline"]["false_positive_rate"], metrics["tuned"]["false_positive_rate"]]

    x = range(len(labels))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    width = 0.24
    ax.bar([i - width for i in x], precision, width, label="Precision")
    ax.bar(list(x), recall, width, label="Recall")
    ax.bar([i + width for i in x], fpr, width, label="FPR")
    ax.set_xticks(list(x), labels)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Rate")
    ax.set_title("Detection Quality Before vs. After Tuning")
    ax.legend()
    fig.tight_layout()
    fig.savefig(outdir / "detection_quality.png", dpi=160)
    plt.close(fig)
