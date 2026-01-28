
import pandas as pd
import io, re

KEYWORDS = ["error","failed","denied","authentication","unauthorized","invalid"]

def analyze_log(file_like):
    if hasattr(file_like, "read"):
        content = file_like.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="ignore")
    else:
        with open(file_like, "r", errors="ignore") as f:
            content = f.read()
    lines = content.splitlines()
    alerts = []
    for i, line in enumerate(lines):
        low = line.lower()
        for kw in KEYWORDS:
            if kw in low:
                # naive timestamp extraction
                ts = None
                m = re.search(r'([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})', line)
                if m:
                    ts = m.group(1)
                alerts.append({"line_no": i+1, "line": line, "keyword": kw, "timestamp": ts})
                break
    df = pd.DataFrame(alerts)
    return df

def extract_ips(df):
    import re
    ips = []
    for line in df["line"].tolist():
        found = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
        ips += found
    return pd.Series(list(set(ips)))
