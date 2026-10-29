#!/usr/bin/env python3
"""
Denny pasivny prieskum assetov (crt.sh + DNS + RIPEstat + Shodan InternetDB + Shodan CVEDB).
Bez API klucov, iba standardna kniznica Pythonu.

Vystup: docs/data/assets.json (cita ho webova stranka docs/index.html)

Nastavenie cez premenne prostredia (alebo argumenty):
  DOMAINS        domeny oddelene ciarkou          (default: orange.sk)
  ASNS           ASN oddelene ciarkou, napr. 12345 (volitelne)
  PUBLISH_MODE   summary | full                    (default: summary)
  SCAN_PREFIXES  1 = dopytaj aj IP z prefixov ASN  (default: 0)
  MAX_IPS        limit IP z prefixov               (default: 500)

summary = publikuje len hostname, porty a POCTY zranitelnosti podla kritickosti
          (bez IP adries a bez zoznamu CVE) - bezpecna volba pre verejnu stranku.
full    = publikuje aj IP, CVE ID, CPE. Pouzi len ak je vystup chraneny/autorizovany.
"""
import argparse
import ipaddress
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

UA = {"User-Agent": "Mozilla/5.0 (asset-status-osint)"}
OUT_FILE = Path("docs/data/assets.json")
CACHE_FILE = Path("data/cve_cache.json")
SEV_ORDER = ["critical", "high", "medium", "low", "unknown", "none"]
CACHE_TTL = timedelta(days=7)


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def http_json(url, timeout=60, retries=3):
    """GET -> JSON. None pri 404, vynimka pri inych chybach."""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code in (429, 500, 502, 503, 504) and attempt < retries - 1:
                time.sleep(3 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            if attempt < retries - 1:
                time.sleep(3 * (attempt + 1))
                continue
            raise


def severity(cvss):
    if cvss is None:
        return "unknown"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "unknown"


# ---------- zdroje ----------
def get_prefixes(asn):
    asn = str(asn).upper().replace("AS", "").strip()
    url = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS" + asn
    try:
        data = http_json(url)
    except Exception as e:  # noqa: BLE001
        print(f"[!] RIPEstat AS{asn}: {e}", file=sys.stderr)
        return []
    out = []
    for p in (data or {}).get("data", {}).get("prefixes", []):
        try:
            out.append(ipaddress.ip_network(p["prefix"], strict=False))
        except (ValueError, KeyError):
            pass
    return out


def get_subdomains(domain):
    url = "https://crt.sh/?q=" + urllib.parse.quote("%." + domain) + "&output=json"
    data = http_json(url, timeout=120, retries=4) or []
    names = set()
    for entry in data:
        for n in entry.get("name_value", "").splitlines():
            n = n.strip().lower().lstrip("*.")
            if n == domain or n.endswith("." + domain):
                names.add(n)
    return sorted(names)


def resolve(host):
    try:
        return host, sorted(set(socket.gethostbyname_ex(host)[2]))
    except (socket.gaierror, socket.herror, UnicodeError):
        return host, []


def internetdb(ip):
    try:
        data = http_json(f"https://internetdb.shodan.io/{ip}", timeout=30)
    except Exception as e:  # noqa: BLE001
        print(f"[!] InternetDB {ip}: {e}", file=sys.stderr)
        return ip, None
    time.sleep(0.2)
    return ip, data


# ---------- CVE obohatenie (Shodan CVEDB, bez kluca) ----------
def load_cache():
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def fresh(entry):
    try:
        return datetime.now(timezone.utc) - datetime.fromisoformat(entry["fetched"]) < CACHE_TTL
    except (KeyError, ValueError, TypeError):
        return False


def fetch_cve(cid):
    try:
        d = http_json(f"https://cvedb.shodan.io/cve/{cid}", timeout=30)
    except Exception as e:  # noqa: BLE001
        print(f"[!] CVEDB {cid}: {e}", file=sys.stderr)
        return cid, None
    time.sleep(0.1)
    if not d:
        return cid, {"cvss": None, "kev": False, "epss": None, "fetched": now_iso()}
    cvss = d.get("cvss_v3")
    if cvss is None:
        cvss = d.get("cvss")
    return cid, {"cvss": cvss, "kev": bool(d.get("kev")),
                 "epss": d.get("epss"), "fetched": now_iso()}


def enrich_cves(cve_ids, threads=5):
    cache = load_cache()
    todo = [c for c in sorted(cve_ids) if c not in cache or not fresh(cache[c])]
    print(f"[*] CVE: {len(cve_ids)} unikatnych, {len(todo)} treba stiahnut")
    with ThreadPoolExecutor(threads) as ex:
        for cid, info in ex.map(fetch_cve, todo):
            if info is not None:
                cache[cid] = info
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(cache, indent=1, sort_keys=True), encoding="utf-8")
    return cache


# ---------- hlavny tok ----------
def main():
    env = os.environ.get
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", action="append")
    ap.add_argument("--asn", action="append")
    ap.add_argument("--mode", choices=["summary", "full"], default=env("PUBLISH_MODE") or "summary")
    ap.add_argument("--scan-prefixes", action="store_true", default=env("SCAN_PREFIXES") == "1")
    ap.add_argument("--max-ips", type=int, default=int(env("MAX_IPS") or 500))
    ap.add_argument("--threads", type=int, default=10)
    args = ap.parse_args()

    domains = args.domain or [d.strip() for d in (env("DOMAINS") or "orange.sk").split(",") if d.strip()]
    asns = args.asn or [a.strip() for a in (env("ASNS") or "").split(",") if a.strip()]

    # 1) prefixy
    prefixes = []
    for a in asns:
        p = get_prefixes(a)
        print(f"[*] AS{a}: {len(p)} prefixov")
        prefixes += p

    def in_prefix(ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in p for p in prefixes if p.version == addr.version)

    # 2) subdomeny -> IP
    host_ips = {}
    for d in domains:
        print(f"[*] crt.sh: {d}")
        try:
            subs = get_subdomains(d)
        except Exception as e:  # noqa: BLE001
            print(f"[!] crt.sh zlyhalo: {e}", file=sys.stderr)
            subs = []
        print(f"    -> {len(subs)} subdomen")
        with ThreadPoolExecutor(args.threads) as ex:
            for host, ips in ex.map(resolve, subs):
                for ip in ips:
                    host_ips.setdefault(ip, set()).add(host)

    if not host_ips and not prefixes:
        sys.exit("Ziadne data (crt.sh/RIPEstat zlyhali?). Neprepisujem existujuci vystup.")

    # 3) volitelne IP z prefixov
    if args.scan_prefixes:
        added = 0
        for net in sorted((p for p in prefixes if p.version == 4), key=lambda n: n.num_addresses):
            for ip in net.hosts():
                if added >= args.max_ips:
                    break
                s = str(ip)
                if s not in host_ips:
                    host_ips[s] = set()
                    added += 1
        print(f"[*] Z prefixov pridanych {added} IP")

    # 4) InternetDB
    ips = sorted(host_ips, key=ipaddress.ip_address)
    print(f"[*] InternetDB: {len(ips)} IP")
    raw = {}
    with ThreadPoolExecutor(min(args.threads, 5)) as ex:
        for ip, data in ex.map(internetdb, ips):
            if data is None and not host_ips[ip]:
                continue
            raw[ip] = data or {}

    # 5) CVE obohatenie
    all_cves = {c for d in raw.values() for c in d.get("vulns", [])}
    cache = enrich_cves(all_cves)

    # 6) zostavenie zaznamov
    assets = []
    for ip, d in raw.items():
        cves = []
        for cid in sorted(d.get("vulns", [])):
            info = cache.get(cid, {})
            cvss = info.get("cvss")
            cves.append({"id": cid, "cvss": cvss, "severity": severity(cvss),
                         "kev": bool(info.get("kev")), "epss": info.get("epss")})
        counts = {s: sum(1 for c in cves if c["severity"] == s)
                  for s in ("critical", "high", "medium", "low", "unknown")}
        max_sev = next((s for s in SEV_ORDER[:5] if counts.get(s)), "none")
        scores = [c["cvss"] for c in cves if c["cvss"] is not None]
        rec = {
            "names": sorted(host_ips[ip]),
            "ports": sorted(d.get("ports", [])),
            "tags": d.get("tags", []),
            "counts": counts,
            "cve_count": len(cves),
            "kev_count": sum(1 for c in cves if c["kev"]),
            "max_severity": max_sev,
            "max_cvss": max(scores) if scores else None,
        }
        if args.mode == "full":
            rec.update({"ip": ip, "cpes": d.get("cpes", []), "cves": cves,
                        "in_asn_prefix": in_prefix(ip) if prefixes else None})
        elif not rec["names"]:
            continue  # v summary modes nezverejnujeme anonymne IP
        assets.append(rec)

    assets.sort(key=lambda a: (SEV_ORDER.index(a["max_severity"]), -a["cve_count"],
                               a["names"][0] if a["names"] else ""))

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(json.dumps({
        "generated": now_iso(), "mode": args.mode, "domains": domains, "assets": assets,
    }, indent=1, ensure_ascii=False), encoding="utf-8")

    print(f"[+] Hotovo: {len(assets)} assetov, mod={args.mode} -> {OUT_FILE}")


if __name__ == "__main__":
    main()
