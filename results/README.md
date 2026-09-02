# Reproduced benchmark

Command:

```bash
python -m telemetry_lab.cli benchmark --events 120000 --seed 42 --out artifacts
```

Measured result for the committed deterministic seed:

- 120,000 events processed
- baseline recall: 1.000
- tuned recall: 1.000
- baseline false positives: 10,150
- tuned false positives: 6,799
- false-positive reduction: 33.0%

The raw/normalized event JSONL files are intentionally not committed because they are
generated deterministically and are ~90 MB combined. Re-run the command above to recreate them.
