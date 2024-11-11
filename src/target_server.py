"""
target_server.py
-----------------
A minimal Flask "victim" server used as the target for the simulated
traffic (both legitimate users and the DoS attack). Every request is
logged to a CSV file with the fields the detection engine needs:

    timestamp, ip, method, path, status_code, response_time_ms

The server pulls the "source IP" from the X-Forwarded-For header when
present. In the simulation, every virtual client (legit or attacker)
sets this header to its own simulated IP address, which lets us run
many virtual clients from a single machine (127.0.0.1) while still
producing realistic, per-IP traffic logs to detect against.
"""

import csv
import os
import time
import threading
from flask import Flask, request, jsonify
from werkzeug.serving import make_server

LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "traffic_log.csv")
LOG_FIELDS = ["timestamp", "ip", "method", "path", "status_code", "response_time_ms"]

_log_lock = threading.Lock()


def _init_log():
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=LOG_FIELDS)
        writer.writeheader()


def _write_log(row):
    with _log_lock:
        with open(LOG_PATH, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=LOG_FIELDS)
            writer.writerow(row)


def create_app():
    app = Flask(__name__)

    @app.before_request
    def _start_timer():
        request._start_time = time.time()

    @app.after_request
    def _log_request(response):
        elapsed_ms = round((time.time() - getattr(request, "_start_time", time.time())) * 1000, 2)
        source_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        _write_log({
            "timestamp": time.time(),
            "ip": source_ip,
            "method": request.method,
            "path": request.path,
            "status_code": response.status_code,
            "response_time_ms": elapsed_ms,
        })
        return response

    @app.route("/")
    def index():
        return jsonify({"status": "ok", "message": "welcome"})

    @app.route("/api/data")
    def api_data():
        # Simulate a small amount of "work" per request, like a real endpoint would do.
        time.sleep(0.002)
        return jsonify({"status": "ok", "data": [1, 2, 3]})

    return app


class ServerThread(threading.Thread):
    """Runs the Flask app in a background thread so the simulation script
    can start the server, generate traffic against it, then shut it down
    cleanly when the simulation is finished."""

    def __init__(self, host="127.0.0.1", port=5055):
        super().__init__()
        _init_log()
        self.app = create_app()
        self.srv = make_server(host, port, self.app)
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.host, self.port = host, port

    def run(self):
        self.srv.serve_forever()

    def shutdown(self):
        self.srv.shutdown()
