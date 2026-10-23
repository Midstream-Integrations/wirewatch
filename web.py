#!/usr/bin/env python3
"""
wirewatch web: serves the dashboard and a read-only JSON API over HTTPS
with HTTP Basic auth. Standard library only.
"""
import base64
import ipaddress
import re
import hmac
import json
import os
import socket
import sqlite3
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DB_PATH = os.environ.get("WW_DB", "/var/lib/wirewatch/wirewatch.db")
BIND = os.environ.get("WW_BIND", "0.0.0.0")
PORT = int(os.environ.get("WW_PORT", "443"))
CERT = os.environ.get("WW_TLS_CERT", "/etc/wirewatch/tls/cert.pem")
KEY = os.environ.get("WW_TLS_KEY", "/etc/wirewatch/tls/key.pem")
USER = os.environ.get("WW_USER", "admin")
PASSWORD = os.environ.get("WW_PASSWORD", "")
INTEL_DB = os.environ.get("WW_INTEL_DB", "/var/lib/wirewatch/intel.db")
HOME = {c.strip().upper() for c in os.environ.get("WW_HOME_COUNTRIES", "US").split(",") if c.strip()}
ACTIVE_SECONDS = int(os.environ.get("WW_ACTIVE_SECONDS", "600"))
FLAG_CATEGORIES = {c.strip() for c in os.environ.get("WW_FLAG_CATEGORIES",
                   "Malware & phishing,Crypto mining,Stalkerware").split(",") if c.strip()}
FOREIGN_ALLOW = [x.strip().lower() for x in os.environ.get("WW_FOREIGN_ALLOW", "").split(",") if x.strip()]
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

PROTO = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6", 132: "SCTP"}
_svc = {}
def service(proto, port):
    if port is None or port < 0:
        return ""
    k = (proto, port)
    if k not in _svc:
        try:
            _svc[k] = socket.getservbyport(port, "tcp" if proto == 6 else "udp")
        except OSError:
            _svc[k] = ""
    return _svc[k]

def db():
    con = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    if os.path.exists(INTEL_DB):
        try:
            con.execute("ATTACH DATABASE ? AS intel", (f"file:{INTEL_DB}?mode=ro",))
            con.execute("SELECT lat, lon FROM intel.ip_info LIMIT 1")
            con.execute("SELECT 1 FROM intel.name_cat LIMIT 1")
            return con
        except sqlite3.Error:
            try:
                con.execute("DETACH DATABASE intel")
            except sqlite3.Error:
                pass
    # no intel yet: empty stand-ins so every query still works
    con.execute("ATTACH DATABASE ':memory:' AS intel")
    con.executescript("""
        CREATE TABLE intel.ip_info (ip TEXT PRIMARY KEY, scope TEXT, cc TEXT, country TEXT, continent TEXT,
          region TEXT, city TEXT, asn INTEGER, org TEXT, looked_up REAL, lat REAL, lon REAL);
        CREATE TABLE intel.name_cat (name TEXT PRIMARY KEY, category TEXT, source TEXT, matched TEXT);
        CREATE TABLE intel.meta (k TEXT PRIMARY KEY, v TEXT);""")
    return con

HOME_SQL = "(" + ",".join("'%s'" % c for c in sorted(HOME) if re.fullmatch(r"[A-Z]{2}", c)) + ")" if HOME else "('')"
def foreign_sql(alias):
    return f"({alias}.scope = 'public' AND {alias}.cc <> '' AND {alias}.cc NOT IN {HOME_SQL})"

def allowed(ip, name, asn):
    for a in FOREIGN_ALLOW:
        if a.startswith("as") and a[2:].isdigit():
            if asn is not None and str(asn) == a[2:]:
                return True
        elif "/" in a or a.replace(".", "").isdigit() or ":" in a:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(a, strict=False):
                    return True
            except ValueError:
                pass
        elif name and (name.lower() == a or name.lower().endswith("." + a)):
            return True
    return False

GEO_COLS = """gd.cc dst_cc, gd.country dst_country, gd.continent dst_continent, gd.region dst_region,
              gd.city dst_city, gd.asn dst_asn, gd.org dst_org, gd.scope dst_scope"""

def window(qs):
    hours = max(1, min(int(qs.get("hours", ["24"])[0]), 24 * 90))
    return int((time.time() // 3600) * 3600 - (hours - 1) * 3600), hours

def scope_sql(qs, col="f.src"):
    # local=1 (default): only devices on your LAN as initiators
    return f" AND {col} IN (SELECT ip FROM hosts WHERE is_local=1)" if qs.get("local", ["1"])[0] == "1" else ""

def rows(cur):
    return [dict(r) for r in cur.fetchall()]

def decorate(items):
    for it in items:
        p = it.get("proto")
        it["proto_name"] = PROTO.get(p, str(p)) if p is not None else ""
        if "dport" in it:
            if it["dport"] is not None and it["dport"] < 0:
                it["dport"] = None
            it["service"] = service(p, it["dport"])
    return items

# ------------------------------------------------------------ devices ---
# A "device" is a MAC address on your LAN, so one laptop's IPv4 address and all
# of its IPv6 addresses (stable, temporary/privacy, link-local) roll up into one row.
# MACs that sit in front of many IPv4 addresses are routers (traffic from routed
# subnets arrives with the router's MAC), so those stay split by IP.
SHARED_MIN = int(os.environ.get("WW_SHARED_MAC_MIN_IPV4", "3"))
GATEWAY_MACS = {m.strip().lower() for m in os.environ.get("WW_GATEWAY_MACS", "").split(",")
                if re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", m.strip())}

def ip_sort(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return (9, ip)
    if a.version == 4:
        return (0, a.packed)
    if a.is_link_local:
        return (3, a.packed)
    if a.is_private:          # fc00::/7 unique-local
        return (2, a.packed)
    return (1, a.packed)

def load_devices(con):
    """Builds the TEMP devmap table (ip -> device id) and returns {device_id: info}."""
    hcols = {r[1] for r in con.execute("PRAGMA table_info(hosts)")}
    local = rows(con.execute(f"SELECT ip, mac, vendor, first_seen, last_seen{', vlan' if 'vlan' in hcols else ''} FROM hosts WHERE is_local=1"))
    hostnames = dict(con.execute("SELECT mac, hostname FROM mac_names").fetchall())
    v4_per_mac = {}
    for h in local:
        if h["mac"] and ":" not in h["ip"]:
            v4_per_mac[h["mac"]] = v4_per_mac.get(h["mac"], 0) + 1
    shared = {m for m, c in v4_per_mac.items() if c >= SHARED_MIN} | GATEWAY_MACS
    devs, mapping = {}, []
    for h in local:
        m = h["mac"] or ""
        dev = "mac:" + m if m and m not in shared else h["ip"]
        mapping.append((h["ip"], dev))
        routed = m in shared
        d = devs.setdefault(dev, {"id": dev, "mac": "" if routed else m, "vendor": "" if routed else (h["vendor"] or ""), "ips": [],
                                  "first_seen": h["first_seen"], "last_seen": h["last_seen"],
                                  "label": hostnames.get(m, "") if dev.startswith("mac:") else "",
                                  "shared_mac": routed})
        d["ips"].append(h["ip"])
        d["first_seen"] = min(x for x in (d["first_seen"], h["first_seen"]) if x) if (d["first_seen"] or h["first_seen"]) else None
        d["last_seen"] = max(d["last_seen"] or 0, h["last_seen"] or 0)
        if not routed:
            d["vendor"] = d["vendor"] or h["vendor"] or ""
    names = dict(con.execute("SELECT n.ip, n.name FROM names n JOIN hosts h ON h.ip = n.ip WHERE h.is_local=1").fetchall())
    enrich(con, devs, local)
    for d in devs.values():
        d["ips"].sort(key=ip_sort)
        if not d["label"]:
            d["label"] = next((names[i] for i in d["ips"] if names.get(i)), "")
    con.execute("CREATE TEMP TABLE devmap (ip TEXT PRIMARY KEY, dev TEXT)")
    con.executemany("INSERT INTO devmap VALUES (?,?)", mapping)
    return devs

# ------------------------------------------------- VLAN / switch / AP ---
def parse_vlan_map():
    """WW_VLAN_MAP="10.1.10.0/24=10 Office, 10.1.20.0/24=20 Guest Wi-Fi" """
    out = []
    for part in os.environ.get("WW_VLAN_MAP", "").split(","):
        if "=" not in part:
            continue
        cidr, rest = (x.strip() for x in part.split("=", 1))
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        tok = rest.split(None, 1)
        vlan = int(tok[0]) if tok and tok[0].isdigit() else None
        name = tok[1] if vlan is not None and len(tok) > 1 else ("" if vlan is not None else rest)
        out.append((net, vlan, name))
    return out
VLAN_MAP = parse_vlan_map()

def table_exists(con, name):
    return con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None

def subnet_lookup(ip, subnets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best = None
    for net, vlan, name, src in subnets:
        if a.version == net.version and a in net and (best is None or net.prefixlen > best[0].prefixlen):
            best = (net, vlan, name, src)
    return best

def enrich(con, devs, local_rows):
    """Adds vlan, network and where-it-plugs-in to each device, best source first:
    UniFi client record > 802.1Q tag on captured frames > WW_VLAN_MAP > UniFi network subnets."""
    uc_by_mac, uc_by_ip = {}, {}
    if table_exists(con, "unifi_clients"):
        for r in rows(con.execute("SELECT * FROM unifi_clients")):
            uc_by_mac[r["mac"]] = r
            if r["ip"]:
                uc_by_ip[r["ip"]] = r
    subnets = [(n, v, nm, "your VLAN map") for n, v, nm in VLAN_MAP]
    if table_exists(con, "unifi_networks"):
        for r in rows(con.execute("SELECT name, vlan, subnet FROM unifi_networks WHERE subnet <> ''")):
            try:
                subnets.append((ipaddress.ip_network(r["subnet"], strict=False), r["vlan"], r["name"], "UniFi network subnet"))
            except ValueError:
                pass
    tags = {}
    if any("vlan" in r for r in local_rows):
        tags = {r["ip"]: r["vlan"] for r in local_rows if r.get("vlan") is not None}
    for d in devs.values():
        uc = uc_by_mac.get(d["mac"]) if d["mac"] else None
        if uc is None:
            uc = next((uc_by_ip[i] for i in d["ips"] if i in uc_by_ip), None)
        vlan, vsrc, net = None, "", ""
        if uc:
            vlan, net, vsrc = uc["vlan"], uc["network"] or "", "UniFi"
            if uc["name"]:
                d["label"] = uc["name"]
            elif not d["label"] and uc["hostname"]:
                d["label"] = uc["hostname"]
            if uc["is_wired"]:
                d["connection"] = {"type": "wired", "switch": uc["switch_name"], "port": uc["port_name"],
                                   "port_idx": uc["port_idx"], "seen": uc["last_seen"]}
            else:
                d["connection"] = {"type": "wireless", "ap": uc["ap_name"], "ssid": uc["essid"], "seen": uc["last_seen"]}
        if vlan is None:
            t = next((tags[i] for i in d["ips"] if i in tags), None)
            if t is not None:
                vlan, vsrc = t, "802.1Q tag"
        if vlan is None or not net:
            hit = next((h for h in (subnet_lookup(i, subnets) for i in d["ips"] if ":" not in i) if h), None)
            if hit:
                if vlan is None and hit[1] is not None:
                    vlan, vsrc = hit[1], hit[3]
                if vlan is None or hit[1] is None or hit[1] == vlan:
                    net = net or hit[2] or ""
        d["vlan"], d["vlan_source"], d["network"] = vlan, vsrc, net
        d.setdefault("connection", None)

def dev_info(devs, dev_id, con=None):
    if dev_id in devs:
        return devs[dev_id]
    info = {"id": dev_id, "mac": "", "vendor": "", "ips": [dev_id], "label": "", "first_seen": None, "last_seen": None}
    if con is not None:
        h = con.execute("SELECT h.mac, h.vendor, h.first_seen, h.last_seen, n.name FROM hosts h "
                        "LEFT JOIN names n ON n.ip = h.ip WHERE h.ip = ?", (dev_id,)).fetchone()
        if h:
            info.update(mac=h["mac"] or "", vendor=h["vendor"] or "", first_seen=h["first_seen"],
                        last_seen=h["last_seen"], label=h["name"] or "")
    return info

DEV = "COALESCE(d.dev, f.src)"
JOIN = "LEFT JOIN devmap d ON d.ip = f.src"

# ---------------------------------------------------------------- API ---
def api_summary(qs):
    since, hours = window(qs)
    sc = scope_sql(qs)
    con = db()
    devs = load_devices(con)
    tot = dict(con.execute(f"""
        SELECT COUNT(DISTINCT {DEV}) devices, COUNT(DISTINCT f.dst) destinations,
               COALESCE(SUM(attempts),0) attempts,
               COALESCE(SUM(CASE WHEN proto=6 THEN attempts END),0) tcp_attempts,
               COALESCE(SUM(CASE WHEN proto=6 THEN established END),0) tcp_established,
               COALESCE(SUM(bytes),0) bytes
        FROM flow_hourly f {JOIN} WHERE hour >= ? {sc}""", (since,)).fetchone())
    timeline = rows(con.execute(f"""
        SELECT hour, SUM(attempts) attempts, SUM(bytes) bytes
        FROM flow_hourly f WHERE hour >= ? {sc} GROUP BY hour ORDER BY hour""", (since,)))
    top = [r[0] for r in con.execute(f"""
        SELECT {DEV} FROM flow_hourly f {JOIN} WHERE hour >= ? {sc}
        GROUP BY 1 ORDER BY SUM(attempts) DESC LIMIT 24""", (since,))]
    heat = []
    if top:
        ph = ",".join("?" * len(top))
        heat = rows(con.execute(f"""
            SELECT {DEV} dev, hour, SUM(attempts) attempts FROM flow_hourly f {JOIN}
            WHERE hour >= ? {sc} AND {DEV} IN ({ph}) GROUP BY 1, 2""", (since, *top)))
    meta = dict(con.execute("SELECT k, v FROM meta").fetchall())
    imeta = dict(con.execute("SELECT k, v FROM intel.meta").fetchall())
    foreign = foreign_summary(foreign_rows(con, devs, since))
    flagged = rows(con.execute(f"""
        SELECT nc.category, COUNT(DISTINCT q.qname) names, COUNT(DISTINCT q.src) devices, SUM(q.count) lookups
        FROM dns_queries q JOIN intel.name_cat nc ON nc.name = q.qname
        WHERE q.hour >= ? AND nc.category IN ({",".join("?" * len(FLAG_CATEGORIES)) or "''"})
        GROUP BY 1""", (since, *sorted(FLAG_CATEGORIES))))
    hd = []
    for t in top:
        i = dev_info(devs, t, con)
        hd.append({"id": t, "label": i["label"], "ip": i["ips"][0], "vendor": i["vendor"], "addresses": len(i["ips"])})
    con.close()
    return {"since": since, "hours": hours, "totals": tot, "timeline": timeline,
            "heatmap": {"devices": hd, "cells": heat},
            "last_flush": float(meta.get("last_flush", 0)), "interface": meta.get("interface", ""),
            "unifi_polled": float(meta.get("unifi_polled") or 0), "unifi_error": meta.get("unifi_error", ""),
            "foreign": foreign, "flagged": flagged, "flag_categories": sorted(FLAG_CATEGORIES),
            "intel": {"geo_month": imeta.get("geo_month", ""), "enriched": float(imeta.get("enriched") or 0)}}

def api_devices(qs):
    since, _ = window(qs)
    sc = scope_sql(qs)
    con = db()
    devs = load_devices(con)
    out = rows(con.execute(f"""
        SELECT {DEV} id, SUM(attempts) attempts, SUM(established) established,
               SUM(CASE WHEN proto=6 THEN attempts END) tcp_attempts,
               COUNT(DISTINCT dst) destinations, COUNT(DISTINCT proto||':'||dport) ports,
               SUM(bytes) bytes, MAX(hour) last_hour
        FROM flow_hourly f {JOIN} WHERE hour >= ? {sc} GROUP BY 1
        ORDER BY attempts DESC LIMIT 1000""", (since,)))
    best = {}
    for r in con.execute(f"""
        SELECT {DEV} dev, proto, dport, SUM(attempts) a FROM flow_hourly f {JOIN}
        WHERE hour >= ? {sc} GROUP BY 1, 2, 3""", (since,)):
        if r["dev"] not in best or r["a"] > best[r["dev"]][2]:
            best[r["dev"]] = (r["proto"], r["dport"], r["a"])
    for r in out:
        i = dev_info(devs, r["id"], con)
        r.update(mac=i["mac"], vendor=i["vendor"], ips=i["ips"], label=i["label"],
                 first_seen=i["first_seen"], last_seen=i["last_seen"] or r["last_hour"],
                 vlan=i.get("vlan"), vlan_source=i.get("vlan_source", ""), network=i.get("network", ""),
                 connection=i.get("connection"))
        if r["id"] in best:
            p, d, _ = best[r["id"]]
            d = None if d is None or d < 0 else d
            r["top_port"] = {"proto": PROTO.get(p, str(p)), "port": d, "service": service(p, d)}
    con.close()
    return {"devices": out}

def api_ports(qs):
    since, _ = window(qs)
    sc = scope_sql(qs)
    con = db()
    load_devices(con)
    out = rows(con.execute(f"""
        SELECT proto, dport, SUM(attempts) attempts, SUM(established) established,
               COUNT(DISTINCT {DEV}) devices, COUNT(DISTINCT dst) destinations, SUM(bytes) bytes
        FROM flow_hourly f {JOIN} WHERE hour >= ? {sc}
        GROUP BY proto, dport ORDER BY attempts DESC LIMIT 500""", (since,)))
    con.close()
    return {"ports": decorate(out)}

def api_destinations(qs):
    since, _ = window(qs)
    sc = scope_sql(qs)
    con = db()
    devs = load_devices(con)
    ip2dev = dict(con.execute("SELECT ip, dev FROM devmap").fetchall())
    out = rows(con.execute(f"""
        SELECT f.dst, COALESCE(n.name, '') name, n.source name_source, SUM(attempts) attempts,
               SUM(established) established, COUNT(DISTINCT {DEV}) devices,
               GROUP_CONCAT(DISTINCT proto||'/'||dport) ports, SUM(bytes) bytes, MAX(hour) last_hour,
               {GEO_COLS}, nc.category, {foreign_sql('gd')} foreign_ip
        FROM flow_hourly f {JOIN} LEFT JOIN names n ON n.ip = f.dst
          LEFT JOIN intel.ip_info gd ON gd.ip = f.dst LEFT JOIN intel.name_cat nc ON nc.name = lower(n.name)
        WHERE hour >= ? {sc} GROUP BY f.dst ORDER BY attempts DESC LIMIT 1000""", (since,)))
    for r in out:
        ps = []
        for p in (r.pop("ports") or "").split(",")[:12]:
            if "/" in p:
                pr, d = p.split("/")
                pr = int(pr); d = int(d) if d not in ("", "None") and int(d) >= 0 else None
                ps.append({"proto": PROTO.get(pr, str(pr)), "port": d, "service": service(pr, d)})
        r["ports"] = ps
        dev = ip2dev.get(r["dst"])
        r["device"] = dev
        if not r["name"] and dev in devs:
            r["name"] = devs[dev]["label"]
        r["foreign"] = bool(r.pop("foreign_ip")) and not allowed(r["dst"], r["name"], r["dst_asn"])
        r["flagged"] = r["category"] in FLAG_CATEGORIES
    con.close()
    return {"destinations": out}

def _labeler(devs, ip2dev):
    def lab(ip):
        dev = ip2dev.get(ip, ip)
        i = devs.get(dev)
        return dev, (i["label"] if i and i["label"] else "")
    return lab

def api_flows(qs):
    since, _ = window(qs)
    sc = scope_sql(qs)
    con = db()
    devs = load_devices(con)
    ip2dev = dict(con.execute("SELECT ip, dev FROM devmap").fetchall())
    where, args = [], [since]
    if qs.get("device"):
        ips = dev_info(devs, qs["device"][0])["ips"]
        where.append(f"f.src IN ({','.join('?' * len(ips))})"); args += ips
    for key, col in (("src", "f.src"), ("dst", "f.dst")):
        if qs.get(key):
            where.append(f"{col} = ?"); args.append(qs[key][0])
    if qs.get("port"):
        where.append("f.dport = ?"); args.append(int(qs["port"][0]))
    if qs.get("proto"):
        where.append("f.proto = ?"); args.append(int(qs["proto"][0]))
    if qs.get("q"):
        like = f"%{qs['q'][0]}%"
        where.append("(f.src LIKE ? OR f.dst LIKE ? OR n.name LIKE ? OR CAST(f.dport AS TEXT) = ?)")
        args += [like, like, like, qs["q"][0]]
    extra = (" AND " + " AND ".join(where)) if where else ""
    limit = min(int(qs.get("limit", ["500"])[0]), 5000)
    out = rows(con.execute(f"""
        SELECT f.src, f.dst, f.proto, f.dport, SUM(attempts) attempts, SUM(established) established,
               SUM(packets) packets, SUM(bytes) bytes, MIN(hour) first_hour, MAX(hour) last_hour,
               COUNT(*) active_hours, n.name dst_name, {GEO_COLS}, nc.category, {foreign_sql('gd')} foreign_ip
        FROM flow_hourly f LEFT JOIN names n ON n.ip = f.dst
          LEFT JOIN intel.ip_info gd ON gd.ip = f.dst LEFT JOIN intel.name_cat nc ON nc.name = lower(n.name)
        WHERE hour >= ? {sc} {extra}
        GROUP BY f.src, f.dst, f.proto, f.dport ORDER BY attempts DESC, packets DESC LIMIT {limit}""", args))
    lab = _labeler(devs, ip2dev)
    for r in out:
        r["src_dev"], r["src_label"] = lab(r["src"])
        if not r["dst_name"] and r["dst"] in ip2dev:
            r["dst_name"] = lab(r["dst"])[1]
        r["foreign"] = bool(r.pop("foreign_ip")) and not allowed(r["dst"], r["dst_name"], r["dst_asn"])
        r["flagged"] = r["category"] in FLAG_CATEGORIES
    con.close()
    return {"flows": decorate(out)}

def api_device(qs):
    dev_id = qs.get("id", qs.get("ip", [""]))[0]
    since, _ = window(qs)
    con = db()
    devs = load_devices(con)
    ip2dev = dict(con.execute("SELECT ip, dev FROM devmap").fetchall())
    if dev_id not in devs and dev_id in ip2dev:      # an IP was passed; find its device
        dev_id = ip2dev[dev_id]
    info = dev_info(devs, dev_id, con)
    ips = info["ips"]; ph = ",".join("?" * len(ips))
    timeline = rows(con.execute(f"""
        SELECT hour, SUM(attempts) attempts, SUM(bytes) bytes FROM flow_hourly
        WHERE src IN ({ph}) AND hour >= ? GROUP BY hour ORDER BY hour""", (*ips, since)))
    per_ip = {r["src"]: r for r in rows(con.execute(f"""
        SELECT src, SUM(attempts) attempts, MAX(hour) last_hour FROM flow_hourly
        WHERE src IN ({ph}) AND hour >= ? GROUP BY src""", (*ips, since)))}
    last = dict(con.execute(f"SELECT ip, last_seen FROM hosts WHERE ip IN ({ph})", ips).fetchall())
    addresses = []
    for ip in ips:
        k = ip_sort(ip)[0]
        addresses.append({"ip": ip, "kind": ["IPv4", "IPv6", "IPv6 ULA", "Link-local"][k] if k < 4 else "",
                          "attempts": per_ip.get(ip, {}).get("attempts", 0), "last_seen": last.get(ip)})
    dns = rows(con.execute(f"""
        SELECT q.qname, SUM(q.count) count, nc.category FROM dns_queries q
        LEFT JOIN intel.name_cat nc ON nc.name = q.qname
        WHERE q.src IN ({ph}) AND q.hour >= ?
        GROUP BY q.qname ORDER BY count DESC LIMIT 200""", (*ips, since)))
    inbound = rows(con.execute(f"""
        SELECT src, proto, dport, SUM(attempts) attempts, SUM(established) established
        FROM flow_hourly WHERE dst IN ({ph}) AND hour >= ? GROUP BY src, proto, dport
        ORDER BY attempts DESC LIMIT 200""", (*ips, since)))
    lab = _labeler(devs, ip2dev)
    for r in inbound:
        r["src_dev"], r["src_label"] = lab(r["src"])
    con.close()
    return {"device": info, "addresses": addresses, "timeline": timeline, "dns": dns,
            "inbound": decorate(inbound)}

def foreign_rows(con, devs, since):
    ip2dev = dict(con.execute("SELECT ip, dev FROM devmap").fetchall())
    out = rows(con.execute(f"""
        SELECT f.src, f.dst, f.proto, f.dport, SUM(f.attempts) attempts, SUM(f.established) established,
               SUM(f.bytes) bytes, MAX(f.hour) last_hour, fl.last_seen,
               {foreign_sql('gd')} dst_foreign, {foreign_sql('gs')} src_foreign,
               gd.cc dcc, gd.country dcountry, gd.continent dcont, gd.city dcity, gd.region dregion, gd.org dorg, gd.asn dasn,
               gs.cc scc, gs.country scountry, gs.continent scont, gs.city scity, gs.region sregion, gs.org sorg, gs.asn sasn,
               nd.name dname, ns.name sname, ncd.category dcat, ncs.category scat
        FROM flow_hourly f
          LEFT JOIN flows fl ON fl.src = f.src AND fl.dst = f.dst AND fl.proto = f.proto AND fl.dport = f.dport
          LEFT JOIN intel.ip_info gd ON gd.ip = f.dst LEFT JOIN intel.ip_info gs ON gs.ip = f.src
          LEFT JOIN names nd ON nd.ip = f.dst LEFT JOIN names ns ON ns.ip = f.src
          LEFT JOIN intel.name_cat ncd ON ncd.name = lower(nd.name) LEFT JOIN intel.name_cat ncs ON ncs.name = lower(ns.name)
        WHERE f.hour >= ? AND ({foreign_sql('gd')} OR {foreign_sql('gs')})
        GROUP BY f.src, f.dst, f.proto, f.dport""", (since,)))
    now, res = time.time(), []
    lab = _labeler(devs, ip2dev)
    for r in out:
        inbound = bool(r["src_foreign"]) and not r["dst_foreign"]
        p = "s" if inbound else "d"
        remote, local = (r["src"], r["dst"]) if inbound else (r["dst"], r["src"])
        name = r[p + "name"] or ""
        if allowed(remote, name, r[p + "asn"]):
            continue
        dev, label = lab(local)
        d = r["dport"] if r["dport"] is not None and r["dport"] >= 0 else None
        res.append({"direction": "inbound" if inbound else "outbound", "local": local, "device": dev,
                    "device_label": label, "remote": remote, "remote_name": name,
                    "cc": r[p + "cc"], "country": r[p + "country"], "continent": r[p + "cont"],
                    "city": r[p + "city"], "region": r[p + "region"], "org": r[p + "org"], "asn": r[p + "asn"],
                    "category": r[p + "cat"] or "", "proto": r["proto"], "proto_name": PROTO.get(r["proto"], str(r["proto"])),
                    "dport": d, "service": service(r["proto"], d), "attempts": r["attempts"],
                    "established": r["established"], "bytes": r["bytes"],
                    "last_seen": r["last_seen"] or r["last_hour"] + 3600,
                    "active": bool(r["last_seen"] and now - r["last_seen"] <= ACTIVE_SECONDS)})
    res.sort(key=lambda x: (not x["active"], -(x["last_seen"] or 0)))
    return res

def foreign_summary(items):
    countries = {}
    for x in items:
        c = countries.setdefault(x["cc"], {"cc": x["cc"], "country": x["country"], "connections": 0, "active": 0})
        c["connections"] += 1; c["active"] += x["active"]
    return {"home": sorted(HOME), "active": sum(x["active"] for x in items), "total": len(items),
            "outbound": sum(x["direction"] == "outbound" for x in items),
            "inbound": sum(x["direction"] == "inbound" for x in items),
            "devices": len({x["device"] for x in items}),
            "countries": sorted(countries.values(), key=lambda c: (-c["active"], -c["connections"]))}

def api_foreign(qs):
    since, _ = window(qs)
    con = db()
    devs = load_devices(con)
    items = foreign_rows(con, devs, since)
    con.close()
    return {"summary": foreign_summary(items), "connections": items[:2000]}

def api_geo(qs):
    since, _ = window(qs)
    sc = scope_sql(qs)
    con = db()
    load_devices(con)
    out = rows(con.execute(f"""
        SELECT CASE WHEN gd.scope IS NULL THEN 'pending' WHEN gd.scope <> 'public' THEN gd.scope ELSE COALESCE(NULLIF(gd.cc, ''), '?') END code,
               MAX(gd.country) country, MAX(gd.continent) continent,
               COUNT(DISTINCT f.dst) destinations, SUM(attempts) attempts, COUNT(DISTINCT {DEV}) devices,
               SUM(bytes) bytes, MAX(hour) last_hour
        FROM flow_hourly f {JOIN} LEFT JOIN intel.ip_info gd ON gd.ip = f.dst
        WHERE hour >= ? {sc} GROUP BY 1 ORDER BY attempts DESC""", (since,)))
    special = {"private": "Your network (private addresses)", "local": "Link-local", "multicast": "Multicast and broadcast",
               "cgnat": "Carrier-grade NAT / Tailscale", "reserved": "Reserved addresses", "?": "Unknown location",
               "pending": "Not looked up yet", "invalid": "Invalid"}
    for r in out:
        r["foreign"] = len(r["code"]) == 2 and r["code"].isupper() and r["code"] not in HOME
        if r["code"] in special:
            r["country"], r["continent"] = special[r["code"]], ""
    meta = dict(con.execute("SELECT k, v FROM intel.meta").fetchall())
    con.close()
    return {"countries": out, "home": sorted(HOME), "geo_month": meta.get("geo_month", "")}

def api_categories(qs):
    since, _ = window(qs)
    sc = scope_sql(qs)
    con = db()
    load_devices(con)
    conn = {r["category"]: r for r in rows(con.execute(f"""
        SELECT COALESCE(NULLIF(nc.category, ''), 'Uncategorized') category, SUM(attempts) attempts,
               COUNT(DISTINCT f.dst) destinations, COUNT(DISTINCT {DEV}) devices, SUM(bytes) bytes
        FROM flow_hourly f {JOIN} JOIN names n ON n.ip = f.dst LEFT JOIN intel.name_cat nc ON nc.name = lower(n.name)
        WHERE hour >= ? {sc} GROUP BY 1""", (since,)))}
    sc_q = scope_sql(qs, "q.src")
    look = {r["category"]: r for r in rows(con.execute(f"""
        SELECT COALESCE(NULLIF(nc.category, ''), 'Uncategorized') category, SUM(q.count) lookups,
               COUNT(DISTINCT q.qname) names, COUNT(DISTINCT COALESCE(d.dev, q.src)) lookup_devices
        FROM dns_queries q LEFT JOIN devmap d ON d.ip = q.src LEFT JOIN intel.name_cat nc ON nc.name = q.qname
        WHERE q.hour >= ? {sc_q} GROUP BY 1""", (since,)))}
    out = []
    for c in set(conn) | set(look):
        a, b = conn.get(c, {}), look.get(c, {})
        out.append({"category": c, "attempts": a.get("attempts", 0), "destinations": a.get("destinations", 0),
                    "devices": max(a.get("devices", 0), b.get("lookup_devices", 0)), "bytes": a.get("bytes", 0),
                    "lookups": b.get("lookups", 0), "names": b.get("names", 0), "flagged": c in FLAG_CATEGORIES})
    out.sort(key=lambda x: -(x["attempts"] + x["lookups"]))
    top = {}
    for r in con.execute(f"""
        SELECT nc.category, q.qname, SUM(q.count) c FROM dns_queries q JOIN intel.name_cat nc ON nc.name = q.qname
        WHERE q.hour >= ? {sc_q} AND nc.category <> '' GROUP BY 1, 2 ORDER BY c DESC""", (since,)):
        lst = top.setdefault(r["category"], [])
        if len(lst) < 5:
            lst.append(r["qname"])
    for x in out:
        x["examples"] = top.get(x["category"], [])
    con.close()
    return {"categories": out}

# ------------------------------------------------------------------ map ---
MAP_HOME = os.environ.get("WW_MAP_HOME", "")       # "lat,lon" of your site

def map_home():
    try:
        la, lo = (float(x) for x in MAP_HOME.split(","))
        return {"lat": la, "lon": lo, "set": True}
    except ValueError:
        try:
            from intel import CENTROIDS
            la, lo = CENTROIDS.get(sorted(HOME)[0] if HOME else "US", (37.09, -95.71))
        except Exception:
            la, lo = 37.09, -95.71
        return {"lat": la, "lon": lo, "set": False}

def api_map(qs):
    since, hours = window(qs)
    sc = scope_sql(qs)
    con = db()
    devs = load_devices(con)
    places = {}
    for r in con.execute(f"""
        SELECT gd.cc, gd.country, gd.continent, gd.city, gd.region, ROUND(gd.lat, 1) lat, ROUND(gd.lon, 1) lon,
               {foreign_sql('gd')} foreign_ip, SUM(attempts) attempts, COUNT(DISTINCT f.dst) destinations,
               COUNT(DISTINCT {DEV}) devices, SUM(bytes) bytes, MAX(hour) last_hour
        FROM flow_hourly f {JOIN} JOIN intel.ip_info gd ON gd.ip = f.dst
        WHERE hour >= ? {sc} AND gd.scope = 'public' AND gd.lat IS NOT NULL
        GROUP BY gd.cc, 6, 7""", (since,)):
        k = f"{r['cc']}|{r['lat']}|{r['lon']}"
        places[k] = dict(r, key=k, foreign=bool(r["foreign_ip"]), top=[], categories={}, inbound=0)
        places[k].pop("foreign_ip")
    for r in con.execute(f"""
        SELECT gd.cc, ROUND(gd.lat, 1) lat, ROUND(gd.lon, 1) lon, COALESCE(n.name, f.dst) target,
               COALESCE(NULLIF(nc.category, ''), '') category, SUM(attempts) a
        FROM flow_hourly f JOIN intel.ip_info gd ON gd.ip = f.dst
          LEFT JOIN names n ON n.ip = f.dst LEFT JOIN intel.name_cat nc ON nc.name = lower(n.name)
        WHERE hour >= ? {sc} AND gd.scope = 'public' AND gd.lat IS NOT NULL
        GROUP BY 1, 2, 3, 4 ORDER BY a DESC""", (since,)):
        p = places.get(f"{r['cc']}|{r['lat']}|{r['lon']}")
        if not p:
            continue
        if len(p["top"]) < 5:
            p["top"].append({"name": r["target"], "category": r["category"], "attempts": r["a"]})
        if r["category"]:
            p["categories"][r["category"]] = p["categories"].get(r["category"], 0) + r["a"]
    inbound = rows(con.execute(f"""
        SELECT gs.cc, gs.country, gs.city, ROUND(gs.lat, 1) lat, ROUND(gs.lon, 1) lon,
               {foreign_sql('gs')} foreign_ip, SUM(attempts) attempts, COUNT(DISTINCT f.src) sources,
               COUNT(DISTINCT f.dst) targets, MAX(hour) last_hour
        FROM flow_hourly f JOIN intel.ip_info gs ON gs.ip = f.src
        WHERE hour >= ? AND gs.scope = 'public' AND gs.lat IS NOT NULL
          AND f.dst IN (SELECT ip FROM hosts WHERE is_local = 1)
        GROUP BY gs.cc, 4, 5""", (since,)))
    for r in inbound:
        r["foreign"] = bool(r.pop("foreign_ip"))
    lan = con.execute(f"""
        SELECT COALESCE(SUM(attempts), 0) FROM flow_hourly f LEFT JOIN intel.ip_info gd ON gd.ip = f.dst
        WHERE hour >= ? {sc} AND (gd.scope IS NULL OR gd.scope <> 'public')""", (since,)).fetchone()[0]
    con.close()
    pl = sorted(places.values(), key=lambda p: -p["attempts"])
    return {"home": map_home(), "home_countries": sorted(HOME), "hours": hours, "places": pl, "inbound": inbound,
            "totals": {"attempts": sum(p["attempts"] for p in pl), "places": len(pl),
                       "countries": len({p["cc"] for p in pl}), "foreign_places": sum(p["foreign"] for p in pl),
                       "foreign_countries": len({p["cc"] for p in pl if p["foreign"]}),
                       "inbound_attempts": sum(r["attempts"] for r in inbound), "lan_attempts": lan}}

def api_map_place(qs):
    """Every IP at one map location, with each hostname seen for it."""
    since, _ = window(qs)
    cc = qs.get("cc", [""])[0]
    lat, lon = float(qs["lat"][0]), float(qs["lon"][0])
    inbound = qs.get("direction", ["outbound"])[0] == "inbound"
    con = db()
    devs = load_devices(con)
    ip2dev = dict(con.execute("SELECT ip, dev FROM devmap").fetchall())
    lab = _labeler(devs, ip2dev)
    side, other = ("src", "dst") if inbound else ("dst", "src")
    if inbound:
        sc = " AND f.dst IN (SELECT ip FROM hosts WHERE is_local = 1)"
    else:
        sc = scope_sql(qs)
    rows_ = rows(con.execute(f"""
        SELECT f.{side} ip, f.{other} peer, f.proto, f.dport, SUM(f.attempts) attempts, SUM(f.established) established,
               SUM(f.bytes) bytes, MAX(f.hour) last_hour, MAX(fl.last_seen) last_seen,
               g.org, g.asn, g.city, g.region, g.country, {foreign_sql('g')} foreign_ip
        FROM flow_hourly f JOIN intel.ip_info g ON g.ip = f.{side}
          LEFT JOIN flows fl ON fl.src = f.src AND fl.dst = f.dst AND fl.proto = f.proto AND fl.dport = f.dport
        WHERE f.hour >= ? {sc} AND g.scope = 'public' AND g.cc = ? AND ROUND(g.lat, 1) = ? AND ROUND(g.lon, 1) = ?
        GROUP BY f.{side}, f.{other}, f.proto, f.dport""", (since, cc, round(lat, 1), round(lon, 1))))
    ips = {}
    for r in rows_:
        x = ips.setdefault(r["ip"], {"ip": r["ip"], "org": r["org"] or "", "asn": r["asn"], "city": r["city"] or "",
                                     "region": r["region"] or "", "country": r["country"] or cc,
                                     "foreign": bool(r["foreign_ip"]), "attempts": 0, "established": 0, "bytes": 0,
                                     "last_seen": 0, "ports": {}, "devices": {}, "names": []})
        x["attempts"] += r["attempts"]; x["established"] += r["established"] or 0; x["bytes"] += r["bytes"] or 0
        x["last_seen"] = max(x["last_seen"], r["last_seen"] or (r["last_hour"] + 3600))
        d = r["dport"] if r["dport"] is not None and r["dport"] >= 0 else None
        pk = f"{PROTO.get(r['proto'], r['proto'])} {d}" if d is not None else PROTO.get(r["proto"], str(r["proto"]))
        x["ports"][pk] = x["ports"].get(pk, 0) + r["attempts"]
        dev, label = lab(r["peer"])
        x["devices"][label or r["peer"]] = x["devices"].get(label or r["peer"], 0) + r["attempts"]
    if ips:
        ph = ",".join("?" * len(ips))
        have_ipn = table_exists(con, "ip_names")
        q = f"""SELECT ip, name, source, last_seen, count FROM ip_names WHERE ip IN ({ph})
                UNION ALL SELECT ip, name, source, last_seen, 0 FROM names WHERE ip IN ({ph})""" if have_ipn else \
            f"SELECT ip, name, source, last_seen, 0 count FROM names WHERE ip IN ({ph})"
        seen = {}
        for r in con.execute(q, (*ips, *ips) if have_ipn else tuple(ips)):
            k = (r["ip"], r["name"].lower().rstrip("."))
            if k not in seen or (r["last_seen"] or 0) > (seen[k]["last_seen"] or 0):
                seen[k] = {"name": k[1], "source": r["source"], "last_seen": r["last_seen"], "count": r["count"]}
        cats = {}
        if seen:
            nm = list({k[1] for k in seen})
            for i in range(0, len(nm), 500):
                chunk = nm[i:i + 500]
                cats.update(dict(con.execute(f"SELECT name, category FROM intel.name_cat WHERE name IN ({','.join('?' * len(chunk))})", chunk).fetchall()))
        for (ip, name), v in seen.items():
            v["category"] = cats.get(name, "") or ""
            v["flagged"] = v["category"] in FLAG_CATEGORIES
            ips[ip]["names"].append(v)
    out = []
    for x in ips.values():
        x["names"].sort(key=lambda v: (v["source"] == "dns", -(v["last_seen"] or 0)))
        x["names"] = x["names"][:12]
        x["ports"] = [{"port": k, "attempts": v} for k, v in sorted(x["ports"].items(), key=lambda kv: -kv[1])][:8]
        x["devices"] = [{"name": k, "attempts": v} for k, v in sorted(x["devices"].items(), key=lambda kv: -kv[1])][:8]
        x["flagged"] = any(v["flagged"] for v in x["names"])
        out.append(x)
    out.sort(key=lambda x: -x["attempts"])
    con.close()
    return {"direction": "inbound" if inbound else "outbound", "ips": out[:500], "total_ips": len(out)}

def api_map_events(qs):
    try:
        since = float(qs.get("since", [str(time.time() - 120)])[0])
    except ValueError:
        since = time.time() - 120
    since = max(since, time.time() - 3600)
    local_only = qs.get("local", ["1"])[0] == "1"
    con = db()
    devs = load_devices(con)
    ip2dev = dict(con.execute("SELECT ip, dev FROM devmap").fetchall())
    lab = _labeler(devs, ip2dev)
    out = []
    for r in con.execute(f"""
        SELECT fl.src, fl.dst, fl.proto, fl.dport, fl.last_seen, fl.attempts,
               gd.scope dscope, gd.cc dcc, gd.country dcountry, gd.city dcity, gd.lat dlat, gd.lon dlon, gd.org dorg,
               gs.scope sscope, gs.cc scc, gs.country scountry, gs.city scity, gs.lat slat, gs.lon slon, gs.org sorg,
               {foreign_sql('gd')} dforeign, {foreign_sql('gs')} sforeign,
               n.name dname, nc.category dcat, sh.is_local slocal
        FROM flows fl
          LEFT JOIN intel.ip_info gd ON gd.ip = fl.dst LEFT JOIN intel.ip_info gs ON gs.ip = fl.src
          LEFT JOIN names n ON n.ip = fl.dst LEFT JOIN intel.name_cat nc ON nc.name = lower(n.name)
          LEFT JOIN hosts sh ON sh.ip = fl.src
        WHERE fl.last_seen > ? AND (gd.scope = 'public' OR gs.scope = 'public')
        ORDER BY fl.last_seen DESC LIMIT 400""", (since,)):
        inbound = r["sscope"] == "public" and r["dscope"] != "public"
        if inbound:
            lat, lon, cc, country, city, org, foreign = r["slat"], r["slon"], r["scc"], r["scountry"], r["scity"], r["sorg"], r["sforeign"]
            remote, local, name, cat = r["src"], r["dst"], "", ""
        else:
            if local_only and not r["slocal"]:
                continue
            lat, lon, cc, country, city, org, foreign = r["dlat"], r["dlon"], r["dcc"], r["dcountry"], r["dcity"], r["dorg"], r["dforeign"]
            remote, local, name, cat = r["dst"], r["src"], r["dname"] or "", r["dcat"] or ""
        if lat is None:
            continue
        if allowed(remote, name, None):
            foreign = False
        d = r["dport"] if r["dport"] is not None and r["dport"] >= 0 else None
        out.append({"ts": r["last_seen"], "direction": "inbound" if inbound else "outbound",
                    "local": local, "device": lab(local)[1] or local, "remote": remote, "name": name,
                    "cc": cc, "country": country, "city": city, "org": org, "lat": lat, "lon": lon,
                    "category": cat, "flagged": cat in FLAG_CATEGORIES, "foreign": bool(foreign),
                    "proto": PROTO.get(r["proto"], str(r["proto"])), "port": d, "service": service(r["proto"], d)})
    con.close()
    out.reverse()
    return {"now": time.time(), "events": out}

ROUTES = {"/api/map": api_map, "/api/map/place": api_map_place, "/api/map/events": api_map_events, "/api/foreign": api_foreign, "/api/geo": api_geo, "/api/categories": api_categories,
          "/api/summary": api_summary, "/api/devices": api_devices, "/api/ports": api_ports,
          "/api/destinations": api_destinations, "/api/flows": api_flows, "/api/device": api_device}

# ------------------------------------------------------------- server ---
class Handler(BaseHTTPRequestHandler):
    server_version = "wirewatch"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def authorized(self):
        h = self.headers.get("Authorization", "")
        if not h.startswith("Basic ") or not PASSWORD:
            return False
        try:
            u, _, p = base64.b64decode(h[6:]).decode().partition(":")
        except Exception:
            return False
        return hmac.compare_digest(u, USER) & hmac.compare_digest(p, PASSWORD)

    def send(self, code, body, ctype, cache=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, max-age=86400" if cache else "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self.authorized():
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="wirewatch"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        url = urlparse(self.path)
        if url.path in ROUTES:
            try:
                data = ROUTES[url.path](parse_qs(url.query))
                self.send(200, json.dumps(data).encode(), "application/json")
            except sqlite3.OperationalError as e:
                self.send(503, json.dumps({"error": f"Database not ready: {e}. Is the collector running?"}).encode(),
                          "application/json")
            except (ValueError, KeyError) as e:
                self.send(400, json.dumps({"error": str(e)}).encode(), "application/json")
            return
        page = {"/": "index.html", "/index.html": "index.html", "/map": "map.html", "/map.html": "map.html"}.get(url.path)
        if page:
            with open(os.path.join(STATIC, page), "rb") as f:
                self.send(200, f.read(), "text/html; charset=utf-8")
            return
        if url.path.startswith("/static/vendor/"):
            name = os.path.basename(url.path)
            path = os.path.join(STATIC, "vendor", name)
            types = {".js": "text/javascript; charset=utf-8", ".json": "application/json", ".txt": "text/plain; charset=utf-8"}
            ext = os.path.splitext(name)[1]
            if name and ext in types and os.path.isfile(path):
                with open(path, "rb") as f:
                    self.send(200, f.read(), types[ext], cache=True)
                return
        self.send(404, b"Not found", "text/plain")

def main():
    if not PASSWORD:
        raise SystemExit("Set WW_PASSWORD in /etc/wirewatch/wirewatch.env before starting the web server.")
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    if CERT and os.path.exists(CERT):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(CERT, KEY)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        scheme = "https"
    else:
        scheme = "http"
        print("WARNING: no TLS cert found, serving plain HTTP", flush=True)
    print(f"wirewatch dashboard on {scheme}://{BIND}:{PORT}/", flush=True)
    srv.serve_forever()

if __name__ == "__main__":
    main()
