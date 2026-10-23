#!/usr/bin/env python3
"""
wirewatch UniFi poller

Every few minutes, asks the UniFi Network application which switch port or
access point each client is on, and which network/VLAN it belongs to, and
stores that in the wirewatch database (keyed by MAC address).

Works with UniFi OS consoles (UDM, UDR, UCG, UX, Cloud Key Gen2+, UniFi OS
Server) using an API key, or with a username/password. Older standalone
controllers (port 8443, no UniFi OS) work with WW_UNIFI_LEGACY_CONTROLLER=1
and a username/password. Standard library only.
"""
import hashlib
import http.client
import http.cookiejar
import json
import os
import signal
import socket
import sqlite3
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

URL = os.environ.get("WW_UNIFI_URL", "").rstrip("/")
SITE = os.environ.get("WW_UNIFI_SITE", "default")
API_KEY = os.environ.get("WW_UNIFI_API_KEY", "")
USER = os.environ.get("WW_UNIFI_USER", "")
PASSWORD = os.environ.get("WW_UNIFI_PASSWORD", "")
LEGACY = os.environ.get("WW_UNIFI_LEGACY_CONTROLLER", "0") == "1"
INTERVAL = int(os.environ.get("WW_UNIFI_INTERVAL", "300"))
PIN = os.environ.get("WW_UNIFI_CERT_SHA256", "").replace(":", "").lower()
VERIFY = os.environ.get("WW_UNIFI_VERIFY_TLS", "0") == "1"
DB_PATH = os.environ.get("WW_DB", "/var/lib/wirewatch/wirewatch.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS unifi_clients (
  mac TEXT PRIMARY KEY, name TEXT, hostname TEXT, ip TEXT, is_wired INTEGER,
  network TEXT, vlan INTEGER, switch_mac TEXT, switch_name TEXT, port_idx INTEGER, port_name TEXT,
  ap_mac TEXT, ap_name TEXT, essid TEXT, last_seen REAL, polled REAL);
CREATE TABLE IF NOT EXISTS unifi_networks (
  id TEXT PRIMARY KEY, name TEXT, vlan INTEGER, subnet TEXT, purpose TEXT, polled REAL);
"""

def log(*a):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)

def norm_mac(m):
    return (m or "").lower().replace("-", ":")

class PinnedConnection(http.client.HTTPSConnection):
    pin = ""
    def connect(self):
        super().connect()
        der = self.sock.getpeercert(binary_form=True)
        if hashlib.sha256(der).hexdigest() != self.pin:
            self.sock.close()
            raise ssl.SSLError("UniFi certificate does not match WW_UNIFI_CERT_SHA256")

class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """Skips CA validation (UniFi consoles use self-signed certs) but requires the
    server certificate to match WW_UNIFI_CERT_SHA256."""
    def __init__(self, pin):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        super().__init__(context=ctx)
        PinnedConnection.pin = pin

    def https_open(self, req):
        return self.do_open(PinnedConnection, req, context=self._context)

def cert_fingerprint():
    u = urlparse(URL)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((u.hostname, u.port or 443), timeout=10) as s:
        with ctx.wrap_socket(s, server_hostname=u.hostname) as t:
            return hashlib.sha256(t.getpeercert(binary_form=True)).hexdigest()

class UniFi:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self.jar)]
        if PIN:
            handlers.append(PinnedHTTPSHandler(PIN))
        elif not VERIFY:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self.opener = urllib.request.build_opener(*handlers)
        self.csrf = ""
        self.logged_in = False
        self.base = f"{URL}/api/s/{SITE}" if LEGACY else f"{URL}/proxy/network/api/s/{SITE}"

    def _req(self, url, data=None, method=None):
        headers = {"Accept": "application/json"}
        if API_KEY and not LEGACY:
            headers["X-API-KEY"] = API_KEY
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        with self.opener.open(req, timeout=30) as r:
            tok = r.headers.get("X-CSRF-Token") or r.headers.get("X-Updated-CSRF-Token")
            if tok:
                self.csrf = tok
            return json.loads(r.read() or b"{}")

    def login(self):
        if not (USER and PASSWORD):
            raise RuntimeError("UniFi rejected the API key and no WW_UNIFI_USER/WW_UNIFI_PASSWORD is set")
        path = "/api/login" if LEGACY else "/api/auth/login"
        self._req(URL + path, {"username": USER, "password": PASSWORD, "remember": False})
        self.logged_in = True

    def get(self, path):
        if not API_KEY and not self.logged_in:
            self.login()
        try:
            j = self._req(self.base + path)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403) and USER and PASSWORD:
                self.logged_in = False
                self.login()
                j = self._req(self.base + path)
            else:
                raise
        return j.get("data", j if isinstance(j, list) else [])

def poll(api, con):
    now = time.time()
    devices = api.get("/stat/device")
    sta = api.get("/stat/sta")
    nets = api.get("/rest/networkconf")

    dev_by_mac = {}
    for d in devices:
        ports = {p.get("port_idx"): (p.get("name") or f"Port {p.get('port_idx')}") for p in d.get("port_table") or []}
        dev_by_mac[norm_mac(d.get("mac"))] = {"name": d.get("name") or d.get("model") or d.get("mac"), "ports": ports}

    net_by_id, net_rows = {}, []
    for n in nets:
        if n.get("purpose") in ("wan", "site-vpn", "remote-user-vpn", "vpn-client"):
            continue
        vlan = n.get("vlan") if n.get("vlan_enabled") else None
        if vlan in ("", None):
            vlan = None if n.get("vlan_enabled") else 1      # untagged LAN = VLAN 1
        try:
            vlan = int(vlan) if vlan is not None else None
        except (TypeError, ValueError):
            vlan = None
        net_by_id[n.get("_id")] = (n.get("name"), vlan)
        net_rows.append((n.get("_id"), n.get("name"), vlan, n.get("ip_subnet") or "", n.get("purpose") or "", now))

    rows = []
    for c in sta:
        mac = norm_mac(c.get("mac"))
        if not mac:
            continue
        net_name, net_vlan = net_by_id.get(c.get("network_id"), (c.get("network"), None))
        vlan = c.get("vlan") if c.get("vlan") not in (None, "", 0) else net_vlan
        sw_mac = norm_mac(c.get("sw_mac") or (c.get("last_uplink_mac") if c.get("is_wired") else ""))
        sw = dev_by_mac.get(sw_mac, {})
        port_idx = c.get("sw_port")
        ap_mac = norm_mac(c.get("ap_mac"))
        rows.append((mac, c.get("name") or "", c.get("hostname") or "", c.get("ip") or "",
                     1 if c.get("is_wired") else 0, net_name or c.get("network") or "", vlan,
                     sw_mac, sw.get("name", c.get("last_uplink_name") or "") if sw_mac else "",
                     port_idx, sw.get("ports", {}).get(port_idx, f"Port {port_idx}" if port_idx else ""),
                     ap_mac, dev_by_mac.get(ap_mac, {}).get("name", "") if ap_mac else "",
                     c.get("essid") or "", c.get("last_seen") or now, now))

    con.execute("BEGIN")
    con.executemany("""
        INSERT INTO unifi_clients VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(mac) DO UPDATE SET name=excluded.name, hostname=excluded.hostname, ip=excluded.ip,
          is_wired=excluded.is_wired, network=excluded.network, vlan=excluded.vlan,
          switch_mac=excluded.switch_mac, switch_name=excluded.switch_name, port_idx=excluded.port_idx,
          port_name=excluded.port_name, ap_mac=excluded.ap_mac, ap_name=excluded.ap_name,
          essid=excluded.essid, last_seen=excluded.last_seen, polled=excluded.polled""", rows)
    con.execute("DELETE FROM unifi_networks")
    con.executemany("INSERT INTO unifi_networks VALUES (?,?,?,?,?,?)", net_rows)
    con.execute("INSERT OR REPLACE INTO meta VALUES ('unifi_polled', ?)", (str(now),))
    con.execute("INSERT OR REPLACE INTO meta VALUES ('unifi_error', '')")
    con.commit()
    return len(rows), len(devices), len(net_rows)

def main():
    if "--fingerprint" in sys.argv:
        if not URL:
            raise SystemExit("Set WW_UNIFI_URL first.")
        print(cert_fingerprint())
        return
    if not URL:
        log("WW_UNIFI_URL is not set; UniFi lookups are off. Nothing to do.")
        return
    if not API_KEY and not (USER and PASSWORD):
        raise SystemExit("Set WW_UNIFI_API_KEY (or WW_UNIFI_USER and WW_UNIFI_PASSWORD).")
    if not PIN and not VERIFY:
        log("WARNING: UniFi TLS certificate is not verified. Set WW_UNIFI_CERT_SHA256 "
            "(get it with: unifi.py --fingerprint) to pin it.")

    con = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    con.executescript(SCHEMA + "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);")
    api = UniFi()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    while not stop.is_set():
        try:
            c, d, n = poll(api, con)
            log(f"UniFi: {c} clients, {d} UniFi devices, {n} networks")
        except Exception as e:
            msg = f"{type(e).__name__}: {e}"
            if isinstance(e, urllib.error.HTTPError) and e.code in (401, 403):
                msg = f"UniFi refused the login (HTTP {e.code}). Check the API key or username/password and the site name."
            log("UniFi poll failed:", msg)
            try:
                con.execute("INSERT OR REPLACE INTO meta VALUES ('unifi_error', ?)", (msg,))
            except sqlite3.Error:
                pass
        stop.wait(INTERVAL)

if __name__ == "__main__":
    main()
