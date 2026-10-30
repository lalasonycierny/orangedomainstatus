#!/usr/bin/env python3
"""
Denny pasivny prieskum assetov viacerych firiem (crt.sh + DNS + RIPEstat +
Shodan InternetDB + Shodan CVEDB). Bez API klucov, iba standardna kniznica.

Firmy sa konfiguruju v companies.json (id, name, domains, asns).
Pre kazdeho hosta sa uklada historia (data/history/<company_id>.json) a pri
kazdom behu sa dopocita, co sa od poslednej snimky zmenilo (nove porty,
zmiznute porty, pribudnute/vyriesene CVE, zmena kritickosti). Hosty, ktore
predtym existovali a teraz sa nenasli, su oznacene ako "zmiznute".

Vystup: docs/data/assets.json (cita ho docs/index.html)

Volitelne: ak je nastaveny DNSDUMPSTER_API_KEY, pre kazdu domenu z companies.json
sa raz denne stiahnu vsetky DNS zaznamy cez dnsdumpster.com API (A, NS, MX, TXT,
CNAME...) a zobrazia sa na stranke v samostatnej zalozke "Vsetky DNS zaznamy".
Bezplatny ucet dnsdumpster.com vracia max. 50 zaznamov na domenu.

Premenne prostredia:
  PUBLISH_MODE        summary | full   (default: summary)
  SCAN_PREFIXES       1 = dopytaj aj IP z prefixov ASN (default: 0)
  MAX_IPS             limit IP z prefixov na firmu     (default: 500)
  DNSDUMPSTER_API_KEY API kluc z dnsdumpster.com (volitelne; bez neho sa
                       zalozka DNS zaznamov nedopocita a ponecha predosle data)

summary = hostname, porty a POCTY zranitelnosti (bez IP a bez CVE ID/popisov).
full    = aj IP, CVE ID, popisy, CPE a historia obsahuje aj CVE ID.
          Pouzi len ak je vystup chraneny/autorizovany - inak summary.
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
HISTORY_DIR = Path("data/history")
COMPANIES_FILE = Path(os.environ.get("COMPANIES_FILE", "companies.json"))
SEV_ORDER = ["critical", "high", "medium", "low", "unknown", "none"]
CACHE_TTL = timedelta(days=7)
MAX_SNAPSHOTS = 50
DISAPPEARED_KEEP_DAYS = 60


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def http_json(url, timeout=60, retries=3, headers=None):
    """GET -> JSON. None pri 404, vynimka pri inych chybach (napr. 401/403/429 po vycerpani pokusov)."""
    hdrs = {**UA, **(headers or {})}
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=hdrs)
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
    """{} = IP bez dat (404), None = chyba pri dopyte."""
    try:
        data = http_json(f"https://internetdb.shodan.io/{ip}", timeout=30)
    except Exception as e:  # noqa: BLE001
        print(f"[!] InternetDB {ip}: {e}", file=sys.stderr)
        return ip, None
    time.sleep(0.2)
    return ip, ({} if data is None else data)


# ---------- CVE obohatenie (Shodan CVEDB, bez kluca) ----------
def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False), encoding="utf-8")


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
    cache = load_json(CACHE_FILE, {})
    todo = [c for c in sorted(cve_ids) if c not in cache or not fresh(cache[c])]
    print(f"[*] CVE: {len(cve_ids)} unikatnych, {len(todo)} treba stiahnut")
    with ThreadPoolExecutor(threads) as ex:
        for cid, info in ex.map(fetch_cve, todo):
            if info is not None:
                cache[cid] = info
    save_json(CACHE_FILE, cache)
    return cache


# ---------- zber pre jednu firmu ----------
def collect(company, args, memo):
    prefixes = []
    for a in company.get("asns", []):
        p = get_prefixes(a)
        print(f"    {str(a).upper() if str(a).upper().startswith('AS') else 'AS' + str(a)}: {len(p)} prefixov")
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
    return assets


# ---------- historia a zmeny ----------
def asset_key(asset):
    """Stabilny kluc hosta naprier behmi. Prednostne hostname (verejne viditelne
    uz aj v summary rezime), aby kluc sam o sebe neprezradzoval IP adresu."""
    return asset["names"][0] if asset.get("names") else (asset.get("ip") or "unknown")


def make_snapshot(asset, mode):
    snap = {
        "date": now_iso(),
        "ports": asset["ports"],
        "counts": asset["counts"],
        "max_severity": asset["max_severity"],
        "max_cvss": asset["max_cvss"],
        "cve_count": asset["cve_count"],
        "kev_count": asset["kev_count"],
    }
    if mode == "full":
        snap["cve_ids"] = sorted(c["id"] for c in asset.get("cves", []))
    return snap


def snap_changed(prev, cur):
    if prev is None:
        return True
    keys = ("ports", "counts", "max_severity", "max_cvss", "cve_count", "kev_count", "cve_ids")
    return any(prev.get(k) != cur.get(k) for k in keys)


def diff_snaps(prev, cur, mode):
    changes = {}
    if prev is None:
        changes["new_host"] = True
        return changes
    added_ports = sorted(set(cur["ports"]) - set(prev.get("ports", [])))
    removed_ports = sorted(set(prev.get("ports", [])) - set(cur["ports"]))
    if added_ports:
        changes["ports_added"] = added_ports
    if removed_ports:
        changes["ports_removed"] = removed_ports
    if mode == "full" and ("cve_ids" in cur or "cve_ids" in prev):
        cur_c, prev_c = set(cur.get("cve_ids", [])), set(prev.get("cve_ids", []))
        added, resolved = sorted(cur_c - prev_c), sorted(prev_c - cur_c)
        if added:
            changes["cves_added"] = added
        if resolved:
            changes["cves_resolved"] = resolved
    else:
        delta = {}
        for s in ("critical", "high", "medium", "low", "unknown"):
            dv = cur["counts"].get(s, 0) - prev.get("counts", {}).get(s, 0)
            if dv:
                delta[s] = dv
        if delta:
            changes["severity_delta"] = delta
    if cur["max_severity"] != prev.get("max_severity"):
        changes["severity_from"] = prev.get("max_severity")
        changes["severity_to"] = cur["max_severity"]
    return changes


def apply_history(cid, assets, mode):
    """Pre kazdy asset doplni first_seen/is_new/changes/history a vrati
    zoznam predtym videnych hostov, ktori teraz chybaju (zmiznute)."""
    path = HISTORY_DIR / f"{cid}.json"
    hist = load_json(path, {})
    seen_keys = set()

    for asset in assets:
        key = asset_key(asset)
        seen_keys.add(key)
        entry = hist.setdefault(key, {"first_seen": now_iso(), "last_seen": None,
                                      "names": asset["names"], "snapshots": []})
        entry["names"] = asset["names"]
        entry["last_seen"] = now_iso()
        prev = entry["snapshots"][-1] if entry["snapshots"] else None
        cur = make_snapshot(asset, mode)
        asset["is_new"] = prev is None
        asset["first_seen"] = entry["first_seen"]
        asset["changes"] = diff_snaps(prev, cur, mode)
        if snap_changed(prev, cur):
            entry["snapshots"].append(cur)
            entry["snapshots"] = entry["snapshots"][-MAX_SNAPSHOTS:]
        asset["history"] = entry["snapshots"][-20:][::-1]  # najnovsie prve

    cutoff = datetime.now(timezone.utc) - timedelta(days=DISAPPEARED_KEEP_DAYS)
    disappeared = []
    for key, entry in hist.items():
        if key in seen_keys:
            continue
        try:
            last_seen = datetime.fromisoformat(entry["last_seen"])
        except (KeyError, ValueError, TypeError):
            continue
        if last_seen < cutoff:
            continue
        last_snap = entry["snapshots"][-1] if entry["snapshots"] else {}
        disappeared.append({
            "names": entry.get("names", [key]),
            "first_seen": entry.get("first_seen"),
            "last_seen": entry.get("last_seen"),
            "last_severity": last_snap.get("max_severity", "unknown"),
        })
    disappeared.sort(key=lambda d: d["last_seen"], reverse=True)

    save_json(path, hist)
    return disappeared[:50]


# ---------- DNSDumpster: vsetky DNS zaznamy pre domenu ----------
def _flatten_ips(entry):
    """dnsdumpster vracia pri A/NS/MX zaznamoch zoznam ip objektov {ip, asn, asn_name, ptr,...}."""
    out = []
    for ip in entry.get("ips", []) or []:
        if isinstance(ip, dict):
            out.append({"ip": ip.get("ip", ""), "asn": ip.get("asn", ""),
                        "asn_name": ip.get("asn_name", ""), "ptr": ip.get("ptr", "")})
        elif ip:
            out.append({"ip": str(ip), "asn": "", "asn_name": "", "ptr": ""})
    return out


def normalize_dnsdumpster(data):
    """Zjednoti rozne tvary odpovede (a/ns/mx/txt/cname/soa...) do plocheho zoznamu zaznamov."""
    records = []
    for rtype, items in (data or {}).items():
        if not isinstance(items, list):
            continue
        for entry in items:
            if isinstance(entry, dict) and ("host" in entry or "ips" in entry):
                ips = _flatten_ips(entry)
                records.append({
                    "type": rtype.upper(),
                    "host": entry.get("host", ""),
                    "value": ", ".join(i["ip"] for i in ips if i["ip"]) or entry.get("target", ""),
                    "asn": ", ".join(sorted({i["asn_name"] or i["asn"] for i in ips if (i["asn_name"] or i["asn"])})),
                })
            elif isinstance(entry, dict):
                records.append({"type": rtype.upper(), "host": entry.get("host", entry.get("name", "")),
                                "value": short(json.dumps(entry, ensure_ascii=False), 200), "asn": ""})
            else:
                records.append({"type": rtype.upper(), "host": "", "value": str(entry), "asn": ""})
    records.sort(key=lambda r: (r["type"], r["host"], r["value"]))
    return records


def fetch_dns_records(domain, api_key):
    url = f"https://api.dnsdumpster.com/domain/{urllib.parse.quote(domain)}"
    data = http_json(url, timeout=60, retries=2, headers={"X-API-Key": api_key})
    return normalize_dnsdumpster(data)


def build_dns_section(companies, api_key, previous_dns):
    domains = sorted({d for c in companies for d in c.get("domains", [])})
    out = {}
    if not api_key:
        print("[!] DNSDUMPSTER_API_KEY nie je nastaveny, zalozka DNS zaznamov sa nedopocita "
              "(ponechavam predosle data, ak existuju)", file=sys.stderr)
        for d in domains:
            out[d] = previous_dns.get(d) or {"generated": None, "stale": True, "records": [], "count": 0}
        return out
    for d in domains:
        try:
            records = fetch_dns_records(d, api_key)
            out[d] = {"generated": now_iso(), "stale": False, "records": records, "count": len(records)}
            print(f"[+] dnsdumpster {d}: {len(records)} zaznamov")
        except Exception as e:  # noqa: BLE001
            print(f"[!] dnsdumpster {d}: {e}", file=sys.stderr)
            if d in previous_dns:
                old = dict(previous_dns[d]); old["stale"] = True
                out[d] = old
            else:
                out[d] = {"generated": None, "stale": True, "records": [], "count": 0, "error": str(e)}
        time.sleep(1.5)  # slusne tempo voci API
    return out


def load_previous(mode):
    """Predosle data firiem - pouzijeme ich len ak boli zapisane v rovnakom rezime."""
    d = load_json(OUT_FILE, {})
    if d.get("mode") == mode:
        return {c["id"]: c for c in d.get("companies", [])}
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
            disappeared = apply_history(c["id"], assets, args.mode)
            assets.sort(key=lambda a: (SEV_ORDER.index(a["max_severity"]), -a["cve_count"],
                                       0 if a.get("changes") else 1,
                                       a["names"][0] if a["names"] else ""))
            new_count = sum(1 for a in assets if a.get("is_new"))
            changed_count = sum(1 for a in assets if a.get("changes") and not a.get("is_new"))
            out_companies.append({
                **{k: c[k] for k in ("id", "name", "domains")},
                "generated": now_iso(), "stale": False, "assets": assets,
                "disappeared": disappeared,
                "changes_summary": {"new": new_count, "changed": changed_count,
                                    "disappeared": len(disappeared)},
            })
            print(f"[+] {c['id']}: {len(assets)} assetov, novych {new_count}, "
                  f"zmenenych {changed_count}, zmiznutych {len(disappeared)}")
        elif c["id"] in previous:
            old = previous[c["id"]]
            old["stale"] = True
            out_companies.append(old)
            print(f"[!] {c['id']}: ziadne nove data, ponechavam predosle (stale)")
        else:
            out_companies.append({**{k: c[k] for k in ("id", "name", "domains")},
                                  "generated": None, "stale": True, "assets": [],
                                  "disappeared": [], "changes_summary": {"new": 0, "changed": 0, "disappeared": 0}})

    if not any(c["assets"] for c in out_companies) and not env("DNSDUMPSTER_API_KEY"):
        sys.exit("Ziadne data pre ziadnu firmu. Neprepisujem existujuci vystup.")

    prev_full = load_json(OUT_FILE, {})
    prev_dns = (prev_full.get("dns") or {}).get("domains", {})
    dns_domains = build_dns_section(companies, env("DNSDUMPSTER_API_KEY"), prev_dns)

    save_json(OUT_FILE, {
        "generated": now_iso(), "mode": args.mode, "companies": out_companies,
        "dns": {"generated": now_iso(), "domains": dns_domains},
    })
    print(f"[+] Ulozene -> {OUT_FILE} (rezim {args.mode})")


if __name__ == "__main__":
    main()
