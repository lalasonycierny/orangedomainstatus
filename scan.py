#!/usr/bin/env python3
"""
Denny pasivny prieskum assetov viacerych firiem (crt.sh + DNS + RIPEstat +
Shodan InternetDB + Shodan CVEDB). Bez API klucov, iba standardna kniznica.

Firmy sa konfiguruju v companies.json (id, name, domains, asns).
Vystup: docs/data/assets.json (cita ho docs/index.html)

Premenne prostredia:
  PUBLISH_MODE   summary | full   (default: summary)
  SCAN_PREFIXES  1 = dopytaj aj IP z prefixov ASN (default: 0)
  MAX_IPS        limit IP z prefixov na firmu     (default: 500)

summary = hostname, porty a POCTY zranitelnosti (bez IP a bez CVE ID/popisov).
full    = aj IP, CVE ID, popisy, CPE. Pouzi len ak je vystup chraneny/autorizovany.
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
COMPANIES_FILE = Path(os.environ.get("COMPANIES_FILE", "companies.json"))
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


def short(text, n=300):
    t = " ".join((text or "").split())
    if len(t) <= n:
        return t
    return t[:n].rsplit(" ", 1)[0] + "…"


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
    """{} = IP bez dat (404), None = chyba."""
    try:
        data = http_json(f"https://internetdb.shodan.io/{ip}", timeout=30)
    except Exception as e:  # noqa: BLE001
        print(f"[!] InternetDB {ip}: {e}", file=sys.stderr)
        return ip, None
    time.sleep(0.2)
    return ip, ({} if data is None else data)


# ---------- CVE obohatenie (Shodan CVEDB, bez kluca) ----------
def load_cache():
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def fresh(entry):
    try:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(entry["fetched"])
        return age < CACHE_TTL and "summary" in entry
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
        return cid, {"cvss": None, "kev": False, "epss": None, "summary": "", "fetched": now_iso()}
    cvss = d.get("cvss_v3")
    if cvss is None:
        cvss = d.get("cvss")
    return cid, {"cvss": cvss, "kev": bool(d.get("kev")), "epss": d.get("epss"),
                 "summary": short(d.get("summary")), "fetched": now_iso()}


def enrich_cves(cve_ids, threads=5):
    cache = load_cache()
    todo = [c for c in sorted(cve_ids) if c not in cache or not fresh(cache[c])]
    print(f"[*] CVE: {len(cve_ids)} unikatnych, {len(todo)} treba stiahnut")
    with ThreadPoolExecutor(threads) as ex:
        for cid, info in ex.map(fetch_cve, todo):
            if info is not None:
                cache[cid] = info
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(cache, indent=1, sort_keys=True, ensure_ascii=False), encoding="utf-8")
    return cache


# ---------- zber pre jednu firmu ----------
def collect(company, args, memo):
    prefixes = []
    for a in company.get("asns", []):
        p = get_prefixes(a)
        print(f"    AS{a}: {len(p)} prefixov")
        prefixes += p

    host_ips = {}
    for d in company.get("domains", []):
        try:
            subs = get_subdomains(d)
        except Exception as e:  # noqa: BLE001
            print(f"[!] crt.sh {d}: {e}", file=sys.stderr)
            subs = []
        print(f"    crt.sh {d}: {len(subs)} subdomen")
        with ThreadPoolExecutor(args.threads) as ex:
            for host, ips in ex.map(resolve, subs):
                for ip in ips:
                    host_ips.setdefault(ip, set()).add(host)

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
        print(f"    z prefixov pridanych {added} IP")

    todo = [ip for ip in host_ips if ip not in memo]
    print(f"    InternetDB: {len(todo)} novych IP z {len(host_ips)}")
    with ThreadPoolExecutor(min(args.threads, 5)) as ex:
        for ip, data in ex.map(internetdb, todo):
            memo[ip] = data

    raw = {}
    for ip in sorted(host_ips, key=ipaddress.ip_address):
        d = memo.get(ip) or {}
        if host_ips[ip] or d:
            raw[ip] = d
    return host_ips, prefixes, raw


def build_assets(raw, host_ips, prefixes, cache, mode):
    def in_prefix(ip):
        addr = ipaddress.ip_address(ip)
        return any(addr in p for p in prefixes if p.version == addr.version)

    assets = []
    for ip, d in raw.items():
        cves = []
        for cid in sorted(d.get("vulns", [])):
            info = cache.get(cid, {})
            cvss = info.get("cvss")
            cves.append({"id": cid, "cvss": cvss, "severity": severity(cvss),
                         "kev": bool(info.get("kev")), "epss": info.get("epss"),
                         "summary": info.get("summary", "")})
        counts = {s: sum(1 for c in cves if c["severity"] == s)
                  for s in ("critical", "high", "medium", "low", "unknown")}
        scores = [c["cvss"] for c in cves if c["cvss"] is not None]
        rec = {
            "names": sorted(host_ips[ip]),
            "ports": sorted(d.get("ports", [])),
            "tags": d.get("tags", []),
            "counts": counts,
            "cve_count": len(cves),
            "kev_count": sum(1 for c in cves if c["kev"]),
            "max_severity": next((s for s in SEV_ORDER[:5] if counts.get(s)), "none"),
            "max_cvss": max(scores) if scores else None,
        }
        if mode == "full":
            rec.update({"ip": ip, "cpes": d.get("cpes", []), "cves": cves,
                        "in_asn_prefix": in_prefix(ip) if prefixes else None})
        elif not rec["names"]:
            continue  # v summary rezime nezverejnujeme anonymne IP
        assets.append(rec)
    assets.sort(key=lambda a: (SEV_ORDER.index(a["max_severity"]), -a["cve_count"],
                               a["names"][0] if a["names"] else ""))
    return assets


def load_previous(mode):
    """Predosle data firiem - pouzijeme ich len ak boli v rovnakom rezime."""
    try:
        d = json.loads(OUT_FILE.read_text(encoding="utf-8"))
        if d.get("mode") == mode:
            return {c["id"]: c for c in d.get("companies", [])}
    except (OSError, json.JSONDecodeError, KeyError):
        pass
    return {}


def main():
    env = os.environ.get
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["summary", "full"], default=env("PUBLISH_MODE") or "summary")
    ap.add_argument("--scan-prefixes", action="store_true", default=env("SCAN_PREFIXES") == "1")
    ap.add_argument("--max-ips", type=int, default=int(env("MAX_IPS") or 500))
    ap.add_argument("--threads", type=int, default=10)
    args = ap.parse_args()

    companies = json.loads(COMPANIES_FILE.read_text(encoding="utf-8"))
    previous = load_previous(args.mode)
    memo, collected = {}, {}

    for c in companies:
        print(f"[*] {c['name']} ({c['id']})")
        try:
            collected[c["id"]] = collect(c, args, memo)
        except Exception as e:  # noqa: BLE001
            print(f"[!] {c['id']} zlyhalo: {e}", file=sys.stderr)

    all_cves = {v for _, _, raw in collected.values() for d in raw.values() for v in d.get("vulns", [])}
    cache = enrich_cves(all_cves)

    out_companies = []
    for c in companies:
        got = collected.get(c["id"])
        if got and (got[0] or got[2]):
            assets = build_assets(got[2], got[0], got[1], cache, args.mode)
            out_companies.append({**{k: c[k] for k in ("id", "name", "domains")},
                                  "generated": now_iso(), "stale": False, "assets": assets})
            print(f"[+] {c['id']}: {len(assets)} assetov")
        elif c["id"] in previous:
            old = previous[c["id"]]
            old["stale"] = True
            out_companies.append(old)
            print(f"[!] {c['id']}: ziadne nove data, ponechavam predosle (stale)")
        else:
            out_companies.append({**{k: c[k] for k in ("id", "name", "domains")},
                                  "generated": None, "stale": True, "assets": []})

    if not any(c["assets"] for c in out_companies):
        sys.exit("Ziadne data pre ziadnu firmu. Neprepisujem existujuci vystup.")

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(json.dumps({"generated": now_iso(), "mode": args.mode,
                                    "companies": out_companies}, indent=1, ensure_ascii=False),
                        encoding="utf-8")
    print(f"[+] Ulozene -> {OUT_FILE} (rezim {args.mode})")


if __name__ == "__main__":
    main()
