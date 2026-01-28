
import pandas as pd
import io
from datetime import datetime

def parse_csv(file_like):
    # Accept uploaded file-like object or file path
    if hasattr(file_like, "read"):
        content = file_like.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="ignore")
        df = pd.read_csv(io.StringIO(content))
    else:
        df = pd.read_csv(file_like)
    # Expect columns: timestamp,src,dst,proto,len
    expected = ["timestamp","src","dst","proto","len"]
    for col in expected:
        if col not in df.columns:
            # try to map common alternatives
            if "time" in df.columns:
                df = df.rename(columns={"time":"timestamp"})
    # ensure timestamp is datetime
    try:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    except Exception:
        pass
    return df

def top_ips(df, col="src"):
    s = df.groupby(col).size().reset_index(name="count").rename(columns={col:"ip"}).sort_values("count", ascending=False)
    return s

def protocol_dist(df):
    return df["proto"].value_counts().reset_index().rename(columns={"index":"protocol","proto":"count"})

def detect_spikes(df, window_seconds=5, multiplier=3):
    # compute packets per second
    df = df.copy()
    df["ts"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("ts")
    df.set_index("ts", inplace=True)
    pps = df["src"].resample(f"{window_seconds}S").count().rename("pps").reset_index()
    mean = pps["pps"].mean()
    spikes = pps[pps["pps"] > mean * multiplier]
    return spikes
