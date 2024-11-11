"""
geo_mapper.py
-------------
Maps simulated IP addresses to geographic coordinates for visualization.

Real-world DoS attacks come from geographically distributed botnets, so
the visualization is far more meaningful when attacker IPs resolve to
different countries. Rather than call an external geolocation API (which
would fail for made-up IPs anyway, and would need network access this
project shouldn't depend on), we ship a small built-in IP -> location
table.

Important: the IPs used throughout this project are drawn from the
IANA/RFC 5737 "TEST-NET" ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), which are reserved specifically for documentation and
example use and are never assigned to real hosts. This keeps the whole
simulation self-contained and safe -- nothing here ever points at a real
IP address on the internet.
"""

# Pool of "attacker" IPs, spread across several countries to make the map interesting.
ATTACKER_IP_POOL = {
    "203.0.113.10": {"city": "Moscow", "country": "Russia", "lat": 55.7558, "lon": 37.6173},
    "203.0.113.11": {"city": "Sao Paulo", "country": "Brazil", "lat": -23.5505, "lon": -46.6333},
    "203.0.113.12": {"city": "Lagos", "country": "Nigeria", "lat": 6.5244, "lon": 3.3792},
    "203.0.113.13": {"city": "Hanoi", "country": "Vietnam", "lat": 21.0278, "lon": 105.8342},
    "203.0.113.14": {"city": "Bucharest", "country": "Romania", "lat": 44.4268, "lon": 26.1025},
    "203.0.113.15": {"city": "Jakarta", "country": "Indonesia", "lat": -6.2088, "lon": 106.8456},
    "203.0.113.16": {"city": "Karachi", "country": "Pakistan", "lat": 24.8607, "lon": 67.0011},
    "203.0.113.17": {"city": "Kyiv", "country": "Ukraine", "lat": 50.4501, "lon": 30.5234},
}

# Pool of "legitimate" user IPs (normal background traffic).
LEGIT_IP_POOL = {
    "198.51.100.20": {"city": "Paris", "country": "France", "lat": 48.8566, "lon": 2.3522},
    "198.51.100.21": {"city": "Berlin", "country": "Germany", "lat": 52.5200, "lon": 13.4050},
    "198.51.100.22": {"city": "London", "country": "UK", "lat": 51.5074, "lon": -0.1278},
    "198.51.100.23": {"city": "New York", "country": "USA", "lat": 40.7128, "lon": -74.0060},
    "198.51.100.24": {"city": "Toronto", "country": "Canada", "lat": 43.6532, "lon": -79.3832},
}

ALL_LOCATIONS = {**ATTACKER_IP_POOL, **LEGIT_IP_POOL}


def locate(ip: str):
    """Return {'city', 'country', 'lat', 'lon'} for a known simulated IP,
    or None if the IP isn't in our demo table."""
    return ALL_LOCATIONS.get(ip)
