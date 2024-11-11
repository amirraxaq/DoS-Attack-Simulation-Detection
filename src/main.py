"""
main.py
-------
Entry point for the DoS Attack Simulation & Detection project.

Usage:
    python src/main.py
    python src/main.py --duration 30 --attack-start 10 --attack-duration 10

Pipeline:
    1. Start a local Flask "victim" server (target_server.py)
    2. Generate legitimate + attack traffic against it (traffic_generator.py)
    3. Run rate-based + anomaly-based detection on the resulting logs (detector.py)
    4. Render the timeline chart, top-attackers chart, and geolocation map (visualizer.py)
    5. Print a text summary report to the console (and save it to output/)
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from target_server import ServerThread, LOG_PATH
from traffic_generator import run_simulation
from detector import load_log, per_ip_rate_analysis, global_volume_anomaly, build_report
from visualizer import plot_timeline, plot_top_attackers, build_attacker_map
from geo_mapper import locate

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")


def main():
    parser = argparse.ArgumentParser(description="Simulate and detect a DoS attack.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5055)
    parser.add_argument("--duration", type=int, default=20, help="Total simulation length (s)")
    parser.add_argument("--attack-start", type=int, default=7, help="Seconds until attack begins")
    parser.add_argument("--attack-duration", type=int, default=8, help="Attack length (s)")
    parser.add_argument("--threads-per-attacker", type=int, default=3)
    parser.add_argument("--rate-threshold", type=float, default=15,
                         help="req/s from one IP to flag as attacker")
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    base_url = f"http://{args.host}:{args.port}"

    log(f"Starting target server on {base_url} ...")
    server = ServerThread(host=args.host, port=args.port)
    server.start()
    time.sleep(0.5)  # let the server bind before we hit it

    log("Running traffic simulation (legit users + timed DoS attack)...")
    run_simulation(
        base_url=base_url,
        total_duration=args.duration,
        attack_start=args.attack_start,
        attack_duration=args.attack_duration,
        threads_per_attacker=args.threads_per_attacker,
        progress_cb=log,
    )

    log("Shutting down target server...")
    server.shutdown()
    server.join(timeout=5)

    log("Loading traffic log and running detection...")
    df = load_log(LOG_PATH)
    per_ip_stats = per_ip_rate_analysis(df, rate_threshold=args.rate_threshold)
    timeline = global_volume_anomaly(df)

    report_text = build_report(per_ip_stats, timeline, locate)
    print("\n" + report_text + "\n")

    report_path = os.path.join(OUTPUT_DIR, "detection_report.txt")
    with open(report_path, "w") as f:
        f.write(report_text)

    stats_csv_path = os.path.join(OUTPUT_DIR, "per_ip_stats.csv")
    per_ip_stats.to_csv(stats_csv_path, index=False)

    log("Generating visualizations...")
    plot_timeline(timeline, os.path.join(OUTPUT_DIR, "traffic_timeline.png"))
    plot_top_attackers(per_ip_stats, os.path.join(OUTPUT_DIR, "top_attackers.png"))
    build_attacker_map(per_ip_stats, os.path.join(OUTPUT_DIR, "attacker_map.html"))

    log(f"Done. Outputs written to: {os.path.abspath(OUTPUT_DIR)}")
    log(" - detection_report.txt  (text summary)")
    log(" - per_ip_stats.csv      (raw per-IP stats)")
    log(" - traffic_timeline.png  (traffic-over-time chart)")
    log(" - top_attackers.png     (top attacker IPs chart)")
    log(" - attacker_map.html     (interactive geolocation map)")


if __name__ == "__main__":
    main()
