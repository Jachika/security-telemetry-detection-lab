from __future__ import annotations

def classification_metrics(events: list[dict], alerted_event_ids: set[str]) -> dict:
    tp = fp = tn = fn = 0
    for e in events:
        y = bool(e.get("is_attack", False))
        p = e["event_id"] in alerted_event_ids
        if y and p: tp += 1
        elif (not y) and p: fp += 1
        elif (not y) and (not p): tn += 1
        else: fn += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": fpr,
    }

def false_positive_reduction(baseline: dict, tuned: dict) -> float:
    b = baseline["fp"]
    t = tuned["fp"]
    return ((b - t) / b) if b else 0.0
