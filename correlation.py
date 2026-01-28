
from datetime import datetime
import uuid

def create_incident(title, summary, details, indicators, severity=20):
    inc = {
        "id": str(uuid.uuid4())[:8],
        "title": title,
        "summary": summary,
        "details": details,
        "indicators": indicators,
        "severity": severity,
        "created_at": datetime.utcnow().isoformat()
    }
    return inc

# Simple function to correlate: check overlap in indicators between events
def correlate_events(events):
    # events: list of dicts with 'indicators'
    correlations = []
    for i, a in enumerate(events):
        for j, b in enumerate(events):
            if i >= j: continue
            overlap = set(a.get("indicators", [])) & set(b.get("indicators", []))
            if overlap:
                correlations.append({"a": a["title"], "b": b["title"], "overlap": list(overlap)})
    return correlations
