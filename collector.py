#!/usr/bin/env python3
"""
wirewatch collector

Runs tshark on a capture interface (or reads a pcap file), turns packets into
"who connected to what, on which protocol/port, how often", and stores the
aggregates in SQLite for the dashboard.

Standard library only. Configuration comes from environment variables
(see /etc/wirewatch/wirewatch.env).
"""
import ipaddress
import os
import queue
import signal
import sqlite3
import subprocess
import sys
import threading
import time

# ---------------------------------------------------------------- config ---
IFACE = os.environ.get("WW_IFACE", "eth0")
PCAP_FILE = os.environ.get("WW_PCAP_FILE", "")          # read a file instead of live capture
DB_PATH = os.environ.get("WW_DB", "/var/lib/wirewatch/wirewatch.db")
CAPTURE_FILTER = os.environ.get("WW_CAPTURE_FILTER", "ip or ip6 or (vlan and (ip or ip6))")
LOCAL_NETS = [ipaddress.ip_network(n.strip(), strict=False) for n in os.environ.get(
    "WW_LOCAL_NETS",
    "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fc00::/7,fe80::/10",
).split(",") if n.strip()]
IGNORE_IPS = {s.strip() for s in os.environ.get("WW_IGNORE_IPS", "").split(",") if s.strip()}
FLUSH_SECONDS = int(os.environ.get("WW_FLUSH_SECONDS", "10"))
UDP_SESSION_GAP = int(os.environ.get("WW_UDP_SESSION_GAP", "60"))   # seconds of silence = new UDP "connection"
RETENTION_DAYS = int(os.environ.get("WW_RETENTION_DAYS", "30"))
SESSION_RESET = os.environ.get("WW_SESSION_RESET", "200000")        # tshark -M, keeps memory flat
TSHARK = os.environ.get("WW_TSHARK", "tshark")

FIELDS = [
    "frame.time_epoch", "frame.len", "eth.src", "vlan.id",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "ip.proto", "ipv6.nxt",
    "tcp.srcport", "tcp.dstport", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset",
    "udp.srcport", "udp.dstport",
    "dns.flags.response", "dns.qry.name", "dns.a", "dns.aaaa",
    "tls.handshake.extensions_server_name", "http.host",
    "dhcp.option.hostname", "dhcp.hw.mac_addr",
]
PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 47: "GRE", 50: "ESP", 2: "IGMP", 132: "SCTP"}

def log(*a):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)

# ---------------------------------------------------------------- schema ---
SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS flows (
  src TEXT, dst TEXT, proto INTEGER, dport INTEGER,
  attempts INTEGER DEFAULT 0, established INTEGER DEFAULT 0,
  packets INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0,
  first_seen REAL, last_seen REAL,
  PRIMARY KEY (src, dst, proto, dport));
CREATE TABLE IF NOT EXISTS flow_hourly (
  hour INTEGER, src TEXT, dst TEXT, proto INTEGER, dport INTEGER,
  attempts INTEGER DEFAULT 0, established INTEGER DEFAULT 0,
  packets INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0,
  PRIMARY KEY (hour, src, dst, proto, dport));
CREATE INDEX IF NOT EXISTS fh_src ON flow_hourly(src, hour);
CREATE INDEX IF NOT EXISTS fh_port ON flow_hourly(proto, dport, hour);
CREATE INDEX IF NOT EXISTS fh_dst ON flow_hourly(dst, hour);
CREATE TABLE IF NOT EXISTS hosts (
  ip TEXT PRIMARY KEY, mac TEXT, vendor TEXT, is_local INTEGER,
  first_seen REAL, last_seen REAL);
CREATE INDEX IF NOT EXISTS hosts_local ON hosts(is_local, mac);
CREATE TABLE IF NOT EXISTS mac_names (mac TEXT PRIMARY KEY, hostname TEXT, last_seen REAL);
CREATE TABLE IF NOT EXISTS names (ip TEXT PRIMARY KEY, name TEXT, source TEXT, last_seen REAL);
CREATE TABLE IF NOT EXISTS ip_names (ip TEXT, name TEXT, source TEXT, first_seen REAL, last_seen REAL,
  count INTEGER DEFAULT 0, PRIMARY KEY (ip, name));
CREATE TABLE IF NOT EXISTS dns_queries (
  src TEXT, qname TEXT, hour INTEGER, count INTEGER DEFAULT 0,
  PRIMARY KEY (src, qname, hour));
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS unifi_clients (
  mac TEXT PRIMARY KEY, name TEXT, hostname TEXT, ip TEXT, is_wired INTEGER,
  network TEXT, vlan INTEGER, switch_mac TEXT, switch_name TEXT, port_idx INTEGER, port_name TEXT,
  ap_mac TEXT, ap_name TEXT, essid TEXT, last_seen REAL, polled REAL);
CREATE TABLE IF NOT EXISTS unifi_networks (
  id TEXT PRIMARY KEY, name TEXT, vlan INTEGER, subnet TEXT, purpose TEXT, polled REAL);
"""

# --------------------------------------------------------------- helpers ---
def is_ip(s):
    try:
        ipaddress.ip_address(s.strip("[]"))
        return True
    except ValueError:
        return False

def host_only(h):
    """'example.com:8080' -> 'example.com', '[2001:db8::1]:80' -> '2001:db8::1'"""
    h = (h or "").strip()
    if h.startswith("["):
        return h[1:].split("]")[0]
    return h.split(":")[0] if h.count(":") == 1 else h
_local_cache = {}
def is_local(ip):
    r = _local_cache.get(ip)
    if r is None:
        try:
            a = ipaddress.ip_address(ip)
            r = any(a in n for n in LOCAL_NETS)
        except ValueError:
            r = False
        if len(_local_cache) > 200000:
            _local_cache.clear()
        _local_cache[ip] = r
    return r

def truthy(v):
    return v in ("1", "True", "true")

def first(v):
    return v.split(",", 1)[0] if v else ""

def to_int(v):
    try:
        return int(first(v))
    except ValueError:
        return None

def load_oui():
    """OUI -> vendor, from `tshark -G manuf` (Wireshark 4.2+) or the old manuf file."""
    table = {}
    lines = []
    try:
        lines = subprocess.run([TSHARK, "-G", "manuf"], capture_output=True, text=True, timeout=60).stdout.splitlines()
    except Exception:
        pass
    if not lines:
        for p in ("/usr/share/wireshark/manuf", "/usr/share/wireshark/manuf.txt"):
            if os.path.exists(p):
                with open(p, errors="ignore") as f:
                    lines = f.read().splitlines()
                break
    for line in lines:
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("\t") if p.strip()]
        if len(parts) < 2 or "/" in parts[0]:
            continue
        oui = parts[0].upper().replace("-", ":")
        if len(oui) == 8:
            table[oui] = parts[-1]
    return table

def valid_fields():
    try:
        out = subprocess.run([TSHARK, "-G", "fields"], capture_output=True, text=True, timeout=120).stdout
        known = {l.split("\t")[2] for l in out.splitlines() if l.count("\t") >= 2}
        ok = [f for f in FIELDS if f in known]
        missing = set(FIELDS) - set(ok)
        if missing:
            log("tshark lacks fields, skipping:", ", ".join(sorted(missing)))
        return ok
    except Exception as e:
        log("could not list tshark fields:", e)
        return FIELDS

def supports_session_reset():
    try:
        h = subprocess.run([TSHARK, "-h"], capture_output=True, text=True, timeout=30)
        return " -M " in (h.stdout + h.stderr)
    except Exception:
        return False

# ------------------------------------------------------------ aggregator ---
class Aggregator:
    def __init__(self, db_path, oui):
        self.db = sqlite3.connect(db_path)
        self.db.executescript(SCHEMA)
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(hosts)")}
        if "vlan" not in cols:                       # upgrade older databases
            self.db.execute("ALTER TABLE hosts ADD COLUMN vlan INTEGER")
            self.db.commit()
        self.oui = oui
        self.reset_buffers()
        self.tcp_seen = {}      # (client, server, dport) -> last_ts  (TCP conversations we know the direction of)
        self.udp_seen = {}      # (client, server, proto, dport) -> last_ts
        self.last_prune = time.time()
        self.packets_total = 0

    def reset_buffers(self):
        self.flows = {}      # (src,dst,proto,dport) -> [attempts, established, packets, bytes, first, last]
        self.hourly = {}     # (hour,src,dst,proto,dport) -> [attempts, established, packets, bytes]
        self.hosts = {}      # ip -> [mac, first_ts, last_ts, vlan tag]
        self.mac_names = {}  # mac -> (hostname, ts)
        self.names = {}      # ip -> (name, source, ts)
        self.dns = {}        # (src,qname,hour) -> count
        self.ip_names = {}   # (ip, name) -> [source, first_ts, last_ts, count]  (every name seen for an IP)

    def note_name(self, ip, name, source, ts):
        k = (ip, name.lower().rstrip("."))
        e = self.ip_names.get(k)
        if e is None:
            self.ip_names[k] = [source, ts, ts, 1]
        else:
            e[2] = max(e[2], ts); e[3] += 1
            if source != "dns":
                e[0] = source

    # one counted packet/attempt against a flow, oriented client -> server
    def bump(self, ts, src, dst, proto, dport, attempt=0, est=0, length=0):
        k = (src, dst, proto, dport if dport is not None else -1)
        f = self.flows.get(k)
        if f is None:
            self.flows[k] = [attempt, est, 1, length, ts, ts]
        else:
            f[0] += attempt; f[1] += est; f[2] += 1; f[3] += length
            if ts < f[4]: f[4] = ts
            if ts > f[5]: f[5] = ts
        hk = (int(ts // 3600) * 3600,) + k
        h = self.hourly.get(hk)
        if h is None:
            self.hourly[hk] = [attempt, est, 1, length]
        else:
            h[0] += attempt; h[1] += est; h[2] += 1; h[3] += length

    def handle(self, r):
        ts = float(r.get("frame.time_epoch") or time.time())
        length = to_int(r.get("frame.len")) or 0
        src = first(r.get("ip.src")) or first(r.get("ipv6.src"))
        dst = first(r.get("ip.dst")) or first(r.get("ipv6.dst"))
        if not src or not dst or src in IGNORE_IPS or dst in IGNORE_IPS:
            return
        self.packets_total += 1
        proto = to_int(r.get("ip.proto")) if r.get("ip.proto") else to_int(r.get("ipv6.nxt"))
        mac = first(r.get("eth.src")).lower()

        vlan = to_int(r.get("vlan.id")) if r.get("vlan.id") else None
        hrec = self.hosts.get(src)
        if hrec is None:
            self.hosts[src] = [mac if is_local(src) else "", ts, ts, vlan if is_local(src) else None]
        else:
            if is_local(src) and mac:
                hrec[0] = mac
            if is_local(src) and vlan is not None:
                hrec[3] = vlan
            hrec[2] = ts
        # A local address that only receives (for example a server whose replies are filtered out, or that
        # silently drops scans) still counts as one of your devices, so inbound traffic to it is attributed.
        if dst not in self.hosts and is_local(dst):
            self.hosts[dst] = ["", ts, ts, None]

        # ---- names: DHCP hostnames, DNS answers, TLS SNI, HTTP Host
        hn = first(r.get("dhcp.option.hostname"))
        hmac = first(r.get("dhcp.hw.mac_addr")).lower()
        if hn and hmac:
            self.mac_names[hmac] = (hn, ts)
        qname = first(r.get("dns.qry.name"))
        # Names only count when one of your devices asked: DNS answers sent to it, and the TLS server name /
        # HTTP Host it sent. Requests arriving from the internet carry whatever text the sender chose
        # (scanners send "Host: 239.255.255.250"), so they would otherwise rename your devices.
        if qname:
            if truthy(first(r.get("dns.flags.response"))):
                if is_local(dst):                         # an answer to one of your devices
                    for col in ("dns.a", "dns.aaaa"):
                        for ans in (r.get(col) or "").split(","):
                            if ans:
                                self.names.setdefault(ans, (qname, "dns", ts))
                                self.note_name(ans, qname, "dns", ts)
            elif is_local(src):                           # a lookup by one of your devices
                hk = (src, qname.lower(), int(ts // 3600) * 3600)
                self.dns[hk] = self.dns.get(hk, 0) + 1
        sni = first(r.get("tls.handshake.extensions_server_name"))
        if sni and is_local(src) and not is_ip(sni):
            self.names[dst] = (sni, "tls", ts)
            self.note_name(dst, sni, "tls", ts)
        host = host_only(first(r.get("http.host")))
        if host and is_local(src) and not is_ip(host):
            self.names[dst] = (host, "http", ts)
            self.note_name(dst, host, "http", ts)

        # ---- connections
        if proto == 6:
            sport, dport = to_int(r.get("tcp.srcport")), to_int(r.get("tcp.dstport"))
            syn, ack = truthy(first(r.get("tcp.flags.syn"))), truthy(first(r.get("tcp.flags.ack")))
            if syn and not ack:                                   # client knocking
                self.tcp_seen[(src, dst, dport)] = ts
                self.bump(ts, src, dst, 6, dport, attempt=1, length=length)
            elif syn and ack:                                     # server answered
                self.tcp_seen[(dst, src, sport)] = ts
                self.bump(ts, dst, src, 6, sport, est=1, length=length)
            elif (src, dst, dport) in self.tcp_seen:
                self.tcp_seen[(src, dst, dport)] = ts
                self.bump(ts, src, dst, 6, dport, length=length)
            elif (dst, src, sport) in self.tcp_seen:
                self.tcp_seen[(dst, src, sport)] = ts
                self.bump(ts, dst, src, 6, sport, length=length)
            else:                                                 # mid-stream: guess server = lower port
                if (dport or 0) <= (sport or 0):
                    self.tcp_seen[(src, dst, dport)] = ts
                    self.bump(ts, src, dst, 6, dport, length=length)
                else:
                    self.tcp_seen[(dst, src, sport)] = ts
                    self.bump(ts, dst, src, 6, sport, length=length)
        elif proto == 17:
            sport, dport = to_int(r.get("udp.srcport")), to_int(r.get("udp.dstport"))
            if sport is None or dport is None:                    # e.g. ICMP-quoted UDP
                self.bump(ts, src, dst, 17, dport, length=length)
                return
            fwd, rev = (src, dst, 17, dport), (dst, src, 17, sport)
            if rev in self.udp_seen and fwd not in self.udp_seen:  # reply to a known request
                self.udp_seen[rev] = ts
                self.bump(ts, dst, src, 17, sport, length=length)
                return
            if fwd not in self.udp_seen and dport > sport and sport < 49152 and dport >= 49152:
                # looks like a reply whose request we missed (e.g. capture started mid-flow)
                key, ts_key = (dst, src, 17, sport), rev
            else:
                key, ts_key = fwd, fwd
            last = self.udp_seen.get(ts_key)
            attempt = 1 if (last is None or ts - last > UDP_SESSION_GAP) and key == fwd else 0
            self.udp_seen[ts_key] = ts
            self.bump(ts, key[0], key[1], 17, key[3], attempt=attempt, length=length)
        else:
            # ICMP / other: every packet from the initiator counts as an attempt,
            # unless it's flowing back from a host that was contacted first.
            if (dst, src, proto) in self.udp_seen:
                self.bump(ts, dst, src, proto, None, length=length)
            else:
                self.udp_seen[(src, dst, proto)] = ts
                self.bump(ts, src, dst, proto, None, attempt=1, length=length)

    def vendor(self, mac):
        if not mac:
            return ""
        v = self.oui.get(mac[:8].upper(), "")
        try:
            if not v and int(mac[1], 16) & 0x2:
                v = "Private (randomized MAC)"
        except (ValueError, IndexError):
            pass
        return v

    def flush(self):
        c = self.db.cursor()
        c.execute("BEGIN")
        c.executemany("""
            INSERT INTO flows VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(src,dst,proto,dport) DO UPDATE SET
              attempts=attempts+excluded.attempts, established=established+excluded.established,
              packets=packets+excluded.packets, bytes=bytes+excluded.bytes,
              first_seen=min(first_seen, excluded.first_seen), last_seen=max(last_seen, excluded.last_seen)
        """, [k + tuple(v) for k, v in self.flows.items()])
        c.executemany("""
            INSERT INTO flow_hourly VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(hour,src,dst,proto,dport) DO UPDATE SET
              attempts=attempts+excluded.attempts, established=established+excluded.established,
              packets=packets+excluded.packets, bytes=bytes+excluded.bytes
        """, [k + tuple(v) for k, v in self.hourly.items()])
        c.executemany("""
            INSERT INTO hosts (ip, mac, vendor, is_local, first_seen, last_seen, vlan) VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
              vlan=COALESCE(excluded.vlan, vlan),
              mac=CASE WHEN excluded.mac<>'' THEN excluded.mac ELSE mac END,
              vendor=CASE WHEN excluded.vendor<>'' THEN excluded.vendor ELSE vendor END,
              first_seen=min(first_seen, excluded.first_seen), last_seen=max(last_seen, excluded.last_seen)
        """, [(ip, m, self.vendor(m), int(is_local(ip)), t0, t1, v) for ip, (m, t0, t1, v) in self.hosts.items()])
        c.executemany("""
            INSERT INTO mac_names VALUES (?,?,?)
            ON CONFLICT(mac) DO UPDATE SET hostname=excluded.hostname, last_seen=excluded.last_seen
        """, [(m, n, t) for m, (n, t) in self.mac_names.items()])
        # SNI/HTTP names beat DNS-derived names; DNS only fills gaps or refreshes other DNS names
        c.executemany("""
            INSERT INTO names VALUES (?,?,?,?)
            ON CONFLICT(ip) DO UPDATE SET name=excluded.name, source=excluded.source, last_seen=excluded.last_seen
            WHERE excluded.source<>'dns' OR names.source='dns'
        """, [(ip, n, s, t) for ip, (n, s, t) in self.names.items()])
        c.executemany("""
            INSERT INTO dns_queries VALUES (?,?,?,?)
            ON CONFLICT(src,qname,hour) DO UPDATE SET count=count+excluded.count
        """, [k + (v,) for k, v in self.dns.items()])
        c.executemany("""
            INSERT INTO ip_names VALUES (?,?,?,?,?,?)
            ON CONFLICT(ip, name) DO UPDATE SET last_seen=max(last_seen, excluded.last_seen), count=count+excluded.count,
              source=CASE WHEN excluded.source<>'dns' THEN excluded.source ELSE source END
        """, [k + tuple(v) for k, v in self.ip_names.items()])
        c.execute("INSERT OR REPLACE INTO meta VALUES ('last_flush', ?)", (str(time.time()),))
        c.execute("INSERT OR REPLACE INTO meta VALUES ('interface', ?)", (PCAP_FILE or IFACE,))
        self.db.commit()
        self.reset_buffers()

        now = time.time()
        if now - self.last_prune > 600:
            self.prune(now)

    def prune(self, now):
        cutoff = now - RETENTION_DAYS * 86400
        self.db.execute("DELETE FROM flow_hourly WHERE hour < ?", (cutoff,))
        self.db.execute("DELETE FROM dns_queries WHERE hour < ?", (cutoff,))
        self.db.execute("DELETE FROM flows WHERE last_seen < ?", (cutoff,))
        self.db.execute("DELETE FROM ip_names WHERE last_seen < ?", (cutoff,))
        self.db.commit()
        stale = now - 3600
        self.tcp_seen = {k: t for k, t in self.tcp_seen.items() if t > stale}
        self.udp_seen = {k: t for k, t in self.udp_seen.items() if t > stale}
        self.last_prune = now

# ------------------------------------------------------------------ main ---
def tshark_cmd(fields):
    cmd = [TSHARK, "-n", "-l", "-Q", "-T", "fields",
           "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"]
    if PCAP_FILE:
        cmd += ["-r", PCAP_FILE]
        if CAPTURE_FILTER:
            cmd += ["-Y", "ip or ipv6"]
    else:
        cmd += ["-i", IFACE]
        if CAPTURE_FILTER:
            cmd += ["-f", CAPTURE_FILTER]
        if SESSION_RESET and SESSION_RESET != "0" and supports_session_reset():
            cmd += ["-M", SESSION_RESET]
    for f in fields:
        cmd += ["-e", f]
    return cmd

def main():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    fields = valid_fields()
    agg = Aggregator(DB_PATH, load_oui())
    log(f"loaded {len(agg.oui)} OUI vendors; local nets: {', '.join(map(str, LOCAL_NETS))}")

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    while not stop.is_set():
        cmd = tshark_cmd(fields)
        log("starting:", " ".join(cmd[:12]), "...")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        q = queue.Queue(maxsize=50000)

        def reader():
            for line in proc.stdout:
                q.put(line)
            q.put(None)
        threading.Thread(target=reader, daemon=True).start()
        threading.Thread(target=lambda: [log("tshark:", l.rstrip()) for l in proc.stderr], daemon=True).start()

        next_flush = time.time() + FLUSH_SECONDS
        while not stop.is_set():
            try:
                line = q.get(timeout=1)
            except queue.Empty:
                line = ""
            if line is None:
                break
            if line:
                vals = line.rstrip("\n").split("\t")
                try:
                    agg.handle(dict(zip(fields, vals)))
                except Exception as e:
                    log("skipped packet:", e)
            if time.time() >= next_flush:
                agg.flush()
                next_flush = time.time() + FLUSH_SECONDS
        agg.flush()
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
        if PCAP_FILE:
            log(f"finished reading {PCAP_FILE}: {agg.packets_total} IP packets")
            break
        if not stop.is_set():
            log("tshark exited (code %s); restarting in 5s" % proc.returncode)
            stop.wait(5)
    log("collector stopped")

if __name__ == "__main__":
    main()
