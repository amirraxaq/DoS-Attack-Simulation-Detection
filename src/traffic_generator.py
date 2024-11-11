"""
traffic_generator.py
---------------------
Generates two kinds of traffic against the local target server:

1. Legitimate traffic  - a handful of simulated users making requests
   at a normal, human-like pace for the whole run.
2. Attack traffic       - a DoS-style flood: many threads per attacker
   IP hammering the server as fast as possible, but only during a
   defined attack window in the middle of the run (so the before/after
   in the logs and charts is obvious).

Every virtual client sets its own IP in the X-Forwarded-For header so
the target server's logs contain realistic per-IP traffic.
"""

import random
import threading
import time
import requests

from geo_mapper import ATTACKER_IP_POOL, LEGIT_IP_POOL

ENDPOINTS = ["/", "/api/data"]


def _make_request(base_url, ip):
    path = random.choice(ENDPOINTS)
    try:
        requests.get(f"{base_url}{path}", headers={"X-Forwarded-For": ip}, timeout=2)
    except requests.exceptions.RequestException:
        # Under heavy simulated load some requests may legitimately time out
        # or be refused -- that's expected DoS behavior, not a bug.
        pass


def legit_user_loop(base_url, ip, stop_event, min_delay=0.4, max_delay=1.2):
    """One simulated normal user, making a request every ~0.4-1.2s."""
    while not stop_event.is_set():
        _make_request(base_url, ip)
        time.sleep(random.uniform(min_delay, max_delay))


def attacker_loop(base_url, ip, stop_event, request_delay=0.03):
    """One simulated attacker thread, hammering the server as fast as
    the request_delay allows (default ~33 req/s per thread)."""
    while not stop_event.is_set():
        _make_request(base_url, ip)
        time.sleep(request_delay)


def run_simulation(base_url, total_duration=20, attack_start=7, attack_duration=8,
                    threads_per_attacker=3, progress_cb=None):
    """
    Orchestrates the full simulation timeline:

        [0 ......... attack_start] legit traffic only
        [attack_start .. +attack_duration] legit traffic + DoS flood
        [.......... total_duration] legit traffic only (attack over)

    Returns the wall-clock (start_time, end_time) of the run, and the
    (attack_start_ts, attack_end_ts) window as absolute epoch seconds,
    so the detector/visualizer can line results up against ground truth.
    """
    stop_event = threading.Event()
    threads = []

    run_start = time.time()

    # Start legitimate users for the whole run.
    for ip in LEGIT_IP_POOL:
        t = threading.Thread(target=legit_user_loop, args=(base_url, ip, stop_event), daemon=True)
        t.start()
        threads.append(t)

    if progress_cb:
        progress_cb(f"Legit traffic started ({len(LEGIT_IP_POOL)} simulated users)")

    time.sleep(attack_start)

    # Launch the attack.
    attack_stop_event = threading.Event()
    attacker_threads = []
    attack_start_ts = time.time()
    for ip in ATTACKER_IP_POOL:
        for _ in range(threads_per_attacker):
            t = threading.Thread(target=attacker_loop, args=(base_url, ip, attack_stop_event), daemon=True)
            t.start()
            attacker_threads.append(t)

    if progress_cb:
        progress_cb(f"DoS ATTACK launched ({len(ATTACKER_IP_POOL)} attacker IPs x "
                     f"{threads_per_attacker} threads each)")

    time.sleep(attack_duration)
    attack_stop_event.set()
    attack_end_ts = time.time()

    if progress_cb:
        progress_cb("Attack stopped, legit traffic continues")

    remaining = total_duration - (attack_start + attack_duration)
    if remaining > 0:
        time.sleep(remaining)

    stop_event.set()
    run_end = time.time()

    # Give threads a brief moment to notice the stop_event and exit.
    time.sleep(0.3)

    if progress_cb:
        progress_cb("Simulation complete")

    return {
        "run_start": run_start,
        "run_end": run_end,
        "attack_start": attack_start_ts,
        "attack_end": attack_end_ts,
    }
