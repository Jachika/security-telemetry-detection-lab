from telemetry_lab.generate import generate_events
from telemetry_lab.normalize import normalize_event
from telemetry_lab.detect import detect
from telemetry_lab.evaluate import classification_metrics

def test_generator_count():
    events = list(generate_events(500, seed=1))
    assert len(events) == 500

def test_normalize_and_detect():
    raw = next(iter(generate_events(1, seed=2))).to_dict()
    event = normalize_event(raw)
    assert "event_type" in event
    assert isinstance(detect(event, tuned=True), list)

def test_metrics_shape():
    events = [normalize_event(e.to_dict()) for e in generate_events(1000, seed=3)]
    ids = {a["event_id"] for e in events for a in detect(e, tuned=True)}
    m = classification_metrics(events, ids)
    assert 0 <= m["precision"] <= 1
    assert 0 <= m["recall"] <= 1
    assert 0 <= m["false_positive_rate"] <= 1
