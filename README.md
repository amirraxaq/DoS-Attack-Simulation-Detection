# DoS Attack Simulation & Detection

Simulates and detects Denial-of-Service attacks with attacker geolocation visualization.

This project spins up a local "victim" web server, generates realistic
background traffic plus a timed flood of attack traffic against it,
then runs a detection engine over the resulting logs to identify the
attacker IPs and the attack window — and finally renders the results
as charts and an interactive world map.

Everything runs **entirely locally** against a server this project
starts itself. No real hosts are targeted and no real IP addresses are
used — see [How the simulation works](#how-the-simulation-works) below.

---

## What it does

1. **Simulate** — starts a local Flask server and generates two kinds
   of traffic against it in threads: a handful of well-behaved
   "legitimate users," and, during a defined attack window, a flood
   of high-frequency requests from several simulated "attacker" IPs
   (a classic volumetric DoS pattern).
2. **Detect** — analyzes the resulting request log with two
   techniques:
   - **Per-IP rate thresholding**: flags any source IP whose
     requests/second exceeds a configurable threshold.
   - **Global volume anomaly detection**: a robust (median/MAD-based)
     z-score over the total requests-per-second timeline, which
     pinpoints *when* the attack happened even before you look at
     individual IPs.
3. **Visualize** — renders:
   - a traffic timeline chart with the detected attack window shaded,
   - a bar chart ranking flagged attacker IPs by peak rate,
   - an interactive Leaflet/folium map plotting every attacker's
     (simulated) geolocation, marker size scaled by traffic volume.

## Project structure

```
dos-attack-simulation/
├── README.md
├── requirements.txt
├── src/
│   ├── target_server.py      # Local Flask "victim" server + request logger
│   ├── traffic_generator.py  # Legit-user + DoS-attack traffic threads
│   ├── detector.py           # Rate-based + anomaly-based detection engine
│   ├── geo_mapper.py         # IP -> simulated geolocation lookup table
│   ├── visualizer.py         # Charts + interactive attacker map
│   └── main.py               # CLI entry point / orchestrator
├── data/
│   └── traffic_log.csv       # Raw request log (generated at runtime)
└── output/
    ├── detection_report.txt  # Text summary of the detection results
    ├── per_ip_stats.csv      # Per-IP request stats
    ├── traffic_timeline.png  # Traffic-over-time chart
    ├── top_attackers.png     # Top attacker IPs by peak rate
    └── attacker_map.html     # Interactive geolocation map
```

## Setup

```bash
cd dos-attack-simulation
python -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

Requires Python 3.9+.

## Usage

Run the default simulation (16s total, attack from t+5s to t+11s):

```bash
python src/main.py
```

Customize the timeline and detection sensitivity:

```bash
python src/main.py \
  --duration 30 \
  --attack-start 10 \
  --attack-duration 10 \
  --threads-per-attacker 4 \
  --rate-threshold 15
```

| Flag | Default | Meaning |
|---|---|---|
| `--host` | `127.0.0.1` | Host for the local victim server |
| `--port` | `5055` | Port for the local victim server |
| `--duration` | `20` | Total simulation length, in seconds |
| `--attack-start` | `7` | Seconds into the run before the attack begins |
| `--attack-duration` | `8` | How long the attack lasts, in seconds |
| `--threads-per-attacker` | `3` | Flood threads launched per attacker IP |
| `--rate-threshold` | `15` | Req/s from one IP required to flag it as an attacker |

When it finishes, open `output/attacker_map.html` in a browser to
explore the interactive map, and check `output/detection_report.txt`
for the text summary.

## Sample output

```
============================================================
DoS DETECTION REPORT
============================================================
Total unique source IPs seen : 13
IPs classified as ATTACKER   : 8
Anomalous traffic windows     : 7

Detected attack window (approx): t+5.0s to t+11.0s

------------------------------------------------------------
IP              Peak req/s  Total reqs  Location
------------------------------------------------------------
203.0.113.11    57.0        328         Sao Paulo, Brazil
203.0.113.17    57.0        327         Kyiv, Ukraine
203.0.113.12    56.0        329         Lagos, Nigeria
203.0.113.10    56.0        330         Moscow, Russia
203.0.113.16    56.0        327         Karachi, Pakistan
203.0.113.15    56.0        327         Jakarta, Indonesia
203.0.113.13    55.0        327         Hanoi, Vietnam
203.0.113.14    55.0        327         Bucharest, Romania
------------------------------------------------------------
```

All 8 simulated attacker IPs are correctly flagged, the 5 legitimate
users are correctly left unflagged, and the detected attack window
(t+5s–t+11s) matches the actual attack schedule almost exactly.

## How the simulation works

- **Multiple virtual clients from one machine.** Every simulated
  client (legit or attacker) sends its own address in the
  `X-Forwarded-For` header, and the victim server logs that as the
  source IP. This lets a single machine simulate many distinct
  clients without needing real distributed infrastructure — the same
  technique used in local load-testing labs.
- **Safe, documentation-only IP ranges.** All simulated IPs come from
  the `203.0.113.0/24`, `198.51.100.0/24`, and `192.0.2.0/24` ranges,
  which [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) reserves
  specifically for documentation and examples. They are never
  assigned to real hosts, so nothing in this project ever references
  or targets a real IP address.
- **Geolocation is illustrative, not looked up live.** Because the
  IPs are synthetic, there's nothing for a real geolocation API to
  resolve. `geo_mapper.py` ships a small built-in table pairing each
  simulated attacker/legit IP with a city, so the map visualization
  reflects the kind of geographic spread a real botnet would show.
- **The "attack" is a local load test against your own process.** No
  external host, network, or service is ever contacted — it's simple
  threaded HTTP flooding of a Flask dev server this script starts and
  stops itself.

## Detection approach in more detail

**Rate-based (per-IP):** requests are bucketed into 1-second windows
per source IP. If any IP's peak requests-in-a-window divided by the
window size exceeds `--rate-threshold` (req/s), it's classified
`ATTACKER`. This catches the classic flood signature directly.

**Anomaly-based (global):** the same bucketing is done for total
traffic (all IPs combined) to build a volume timeline. Rather than a
plain mean/std z-score — which breaks down once the attack occupies a
large share of the observed traffic, because the flood itself skews
the mean — the detector uses the **median and Median Absolute
Deviation (MAD)**, both robust to being dragged around by the very
outliers being detected. Windows with a robust z-score above
`zscore_threshold` (2.5 by default) are marked anomalous, which is how
the "detected attack window" in the report is derived.

## Extending this project

- Swap `geo_mapper.py` for a real IP-geolocation API (e.g. MaxMind
  GeoLite2 or ipinfo.io) if you point the detector at **real** traffic
  logs instead of the simulation.
- Add more attack patterns: slow-loris style (many open, slow
  connections) vs. volumetric flood (this project) behave very
  differently and need different detection logic.
- Feed `per_ip_stats.csv` into a simple ML classifier (e.g. isolation
  forest) instead of a fixed threshold, and compare precision/recall
  against the threshold-based approach.
- Add automatic mitigation: once an IP is flagged, simulate rate
  limiting or blocking it and observe the traffic timeline recover.

## Disclaimer

This project is for **educational purposes** — learning how DoS
traffic patterns look and how to detect them. It only ever generates
traffic against a local server it starts itself, using IP addresses
reserved for documentation. Do not repurpose the traffic-generation
code to target systems you do not own or have explicit permission to
test.
