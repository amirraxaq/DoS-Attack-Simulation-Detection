"""
detector.py
-----------
Analyzes the traffic log produced by target_server.py and flags
IP addresses that look like DoS attackers.

Two complementary detection techniques are used, which is standard
practice in real intrusion-detection systems:

1. Rate-based thresholding (per-IP)
   For each source IP, requests are bucketed into fixed-size time
   windows (default 1 second). If an IP's peak requests-per-window
   exceeds `rate_threshold`, it's flagged as an attacker. This catches
   the classic "flood" signature.

2. Global volume anomaly detection (z-score)
   The overall requests-per-second timeline is compared against its
   own rolling mean/std. Windows where traffic spikes more than
   `zscore_threshold` standard deviations above baseline are marked as
   "attack windows" -- useful for flagging *when* an attack happened,
   even before you know *who* did it.

The two signals are combined into a single report: attacker IPs, their
stats, and the detected attack time window(s).
"""

import pandas as pd
import numpy as np


def load_log(log_path):
    df = pd.read_csv(log_path)
    df["timestamp"] = df["timestamp"].astype(float)
    return df


def per_ip_rate_analysis(df, window_seconds=1.0, rate_threshold=15):
    """Bucket each IP's requests into fixed windows and compute peak rate.

    rate_threshold is requests/second sustained *per IP*. A normal human
    user (per our simulator) sends roughly 1-2 req/s at most, so anything
    consistently above ~15 req/s from one IP is a strong flood signal.
    """
    df = df.copy()
    t0 = df["timestamp"].min()
    df["window"] = ((df["timestamp"] - t0) // window_seconds).astype(int)

    grouped = df.groupby(["ip", "window"]).size().reset_index(name="requests")
    per_ip_stats = grouped.groupby("ip")["requests"].agg(
        peak_requests_per_window="max",
        avg_requests_per_window="mean",
        total_windows_active="count",
    ).reset_index()

    per_ip_totals = df.groupby("ip").size().reset_index(name="total_requests")
    per_ip_stats = per_ip_stats.merge(per_ip_totals, on="ip")

    per_ip_stats["peak_rate_per_sec"] = per_ip_stats["peak_requests_per_window"] / window_seconds
    per_ip_stats["classification"] = np.where(
        per_ip_stats["peak_rate_per_sec"] >= rate_threshold, "ATTACKER", "normal"
    )
    return per_ip_stats.sort_values("peak_rate_per_sec", ascending=False).reset_index(drop=True)


def global_volume_anomaly(df, window_seconds=1.0, zscore_threshold=2.5):
    """Detect the time window(s) where total traffic volume spikes
    anomalously above the run's own baseline, using a robust z-score.

    A plain mean/std z-score breaks down when the attack occupies a
    large fraction of the run, because the flood itself drags the mean
    and inflates the std, hiding its own spike. We use the median and
    the Median Absolute Deviation (MAD) instead: both are resistant to
    being skewed by the very outliers we're trying to detect.
    """
    df = df.copy()
    t0 = df["timestamp"].min()
    df["window"] = ((df["timestamp"] - t0) // window_seconds).astype(int)

    timeline = df.groupby("window").size().reset_index(name="requests")
    # Fill any empty windows with 0 so the timeline has no gaps.
    full_range = pd.DataFrame({"window": range(timeline["window"].max() + 1)})
    timeline = full_range.merge(timeline, on="window", how="left").fillna(0)

    median = timeline["requests"].median()
    mad = (timeline["requests"] - median).abs().median()
    mad = mad if mad > 0 else 1.0
    # 0.6745 makes the robust z-score comparable in scale to a normal z-score.
    timeline["zscore"] = 0.6745 * (timeline["requests"] - median) / mad
    timeline["is_anomalous"] = timeline["zscore"] >= zscore_threshold
    timeline["timestamp"] = timeline["window"] * window_seconds + t0

    return timeline


def build_report(per_ip_stats, timeline, geo_lookup):
    attackers = per_ip_stats[per_ip_stats["classification"] == "ATTACKER"].copy()
    anomalous_windows = timeline[timeline["is_anomalous"]]

    lines = []
    lines.append("=" * 60)
    lines.append("DoS DETECTION REPORT")
    lines.append("=" * 60)
    lines.append(f"Total unique source IPs seen : {len(per_ip_stats)}")
    lines.append(f"IPs classified as ATTACKER   : {len(attackers)}")
    lines.append(f"Anomalous traffic windows     : {len(anomalous_windows)}")
    lines.append("")

    if len(anomalous_windows):
        start = anomalous_windows["timestamp"].min()
        end = anomalous_windows["timestamp"].max()
        lines.append(f"Detected attack window (approx): t+{start - timeline['timestamp'].min():.1f}s "
                      f"to t+{end - timeline['timestamp'].min():.1f}s")
        lines.append("")

    lines.append("-" * 60)
    lines.append(f"{'IP':<16}{'Peak req/s':<12}{'Total reqs':<12}{'Location'}")
    lines.append("-" * 60)
    for _, row in attackers.iterrows():
        loc = geo_lookup(row["ip"])
        loc_str = f"{loc['city']}, {loc['country']}" if loc else "unknown"
        lines.append(f"{row['ip']:<16}{row['peak_rate_per_sec']:<12.1f}{row['total_requests']:<12}{loc_str}")

    lines.append("-" * 60)
    return "\n".join(lines)
