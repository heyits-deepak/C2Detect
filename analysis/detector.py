import numpy as np

def detect_beaconing(df, threshold=4, std_limit=2):
    grouped = df.groupby(['id.orig_h', 'id.resp_h'])
    results = []

    for (src, dst), group in grouped:
        times = group['ts'].sort_values()
        if len(times) < threshold:
            continue
        intervals = times.diff().dropna().dt.total_seconds()
        std_dev = intervals.std()
        if std_dev < std_limit:
            results.append((src, dst, len(intervals), std_dev, list(intervals)))
    return results
