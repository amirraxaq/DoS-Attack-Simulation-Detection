"""
visualizer.py
-------------
Produces three outputs into output/:

1. traffic_timeline.png - requests/sec over time, with the detected
   attack window shaded, so you can visually see the flood happen.
2. top_attackers.png    - bar chart of peak request rate per flagged IP.
3. attacker_map.html    - interactive world map (folium) plotting every
   flagged attacker IP at its (simulated) geolocation, marker size
   scaled by how much traffic it sent. Legit traffic sources are shown
   too, in a different color, for contrast.
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import folium

from geo_mapper import locate


def plot_timeline(timeline, out_path, window_seconds=1.0):
    t0 = timeline["timestamp"].min()
    x = timeline["timestamp"] - t0
    y = timeline["requests"]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(x, y, color="#2563eb", linewidth=1.5, label="Requests / window")

    anomalous = timeline[timeline["is_anomalous"]]
    if len(anomalous):
        a_start = anomalous["timestamp"].min() - t0
        a_end = anomalous["timestamp"].max() - t0 + window_seconds
        ax.axvspan(a_start, a_end, color="red", alpha=0.15, label="Detected attack window")

    ax.set_title("Traffic Volume Over Time (DoS Attack Simulation)")
    ax.set_xlabel("Time (seconds since start)")
    ax.set_ylabel(f"Requests per {window_seconds:.0f}s window")
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, dpi=130)
    plt.close(fig)


def plot_top_attackers(per_ip_stats, out_path, top_n=10):
    attackers = per_ip_stats[per_ip_stats["classification"] == "ATTACKER"].head(top_n)
    if attackers.empty:
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    ips = attackers["ip"]
    rates = attackers["peak_rate_per_sec"]
    ax.barh(ips, rates, color="#dc2626")
    ax.set_xlabel("Peak requests / second")
    ax.set_title("Flagged Attacker IPs by Peak Request Rate")
    ax.invert_yaxis()
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, dpi=130)
    plt.close(fig)


def build_attacker_map(per_ip_stats, out_path):
    m = folium.Map(location=[20, 10], zoom_start=2, tiles="OpenStreetMap")

    max_reqs = max(per_ip_stats["total_requests"].max(), 1)

    for _, row in per_ip_stats.iterrows():
        loc = locate(row["ip"])
        if not loc:
            continue
        is_attacker = row["classification"] == "ATTACKER"
        color = "red" if is_attacker else "blue"
        radius = 6 + 20 * (row["total_requests"] / max_reqs) if is_attacker else 5

        popup = folium.Popup(
            f"<b>{row['ip']}</b><br>"
            f"{loc['city']}, {loc['country']}<br>"
            f"Total requests: {row['total_requests']}<br>"
            f"Peak rate: {row['peak_rate_per_sec']:.1f} req/s<br>"
            f"Classification: <b>{row['classification']}</b>",
            max_width=250,
        )

        folium.CircleMarker(
            location=[loc["lat"], loc["lon"]],
            radius=radius,
            color=color,
            fill=True,
            fill_color=color,
            fill_opacity=0.6,
            popup=popup,
        ).add_to(m)

    legend_html = """
    <div style="position: fixed; bottom: 30px; left: 30px; z-index:9999;
                background: white; padding: 10px 14px; border-radius: 6px;
                box-shadow: 0 1px 4px rgba(0,0,0,0.3); font-size: 13px;">
        <b>Legend</b><br>
        <span style="color:red;">&#9679;</span> Attacker IP (size = traffic volume)<br>
        <span style="color:blue;">&#9679;</span> Legitimate user IP
    </div>
    """
    m.get_root().html.add_child(folium.Element(legend_html))

    m.save(out_path)
