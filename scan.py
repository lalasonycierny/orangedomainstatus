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

Volitelne: ak je nastaveny LEAKIX_API_KEY, ku kazdej IP sa navyse dopyta LeakIX host
lookup (https://leakix.net/host/{ip}) a najdene CVE (z tagov sluzieb/leakov v tvare
"cve-RRRR-xxxxx") sa pripoja k existujucim zo Shodanu - kazda zranitelnost ma oznaceny
zdroj ("Shodan", "LeakIX", alebo oboje, ak ju nahlasia obe sluzby). Volania su
limitovane premennou LEAKIX_MAX_CALLS na beh a vysledky sa cachuju (data/leakix_cache.json)
na 7 dni, aby sa zbytocne nemrhalo bezplatnym kreditom. LeakIX vacsinou neudava CVSS skore
k tagu, preto taketo CVE maju kritickost "unknown", kym sa nenajde zhoda v Shodan CVEDB.

Premenne prostredia:
  PUBLISH_MODE        summary | full   (default: summary)
  SCAN_PREFIXES       1 = dopytaj aj IP z prefixov ASN (default: 0)
  MAX_IPS             limit IP z prefixov na firmu     (default: 500)
  DNSDUMPSTER_API_KEY API kluc z dnsdumpster.com (volitelne; bez neho sa
                       zalozka DNS zaznamov nedopocita a ponecha predosle data)
  LEAKIX_API_KEY       API kluc z leakix.net (volitelne)
  LEAKIX_MAX_CALLS     max. poctov volani LeakIX API za jeden beh (default 100)
  MAX_PREFIX_DETAILS   kolko IP prefixov na firmu sa ma obohatit o RIPE whois
                        detail (netname/descr/country) za beh (default 100)
  ZAP_REPORT_PATH       cesta/cesty (ciarkou oddelene) k JSON reportom z OWASP
                        ZAP (volitelne) - viac ciest sa hodi, ak sa skenuje
                        viac hostname naraz (napr. orange.sk aj www.orange.sk),
                        kedze jeden moze zlyhat (napr. connection reset) a iny nie
  NUCLEI_REPORT_PATH    cesta/cesty (ciarkou oddelene) k JSONL vystupu z nuclei -jsonl
  WEBSEC_TARGET_HOSTS   ciarkou oddeleny zoznam hostname, ku ktorym sa smu
                        pripojit ZAP/Nuclei zaznamy (default "orange.sk,www.orange.sk")

WEBSEC (OWASP ZAP / Nuclei) - doplnkove zranitelnosti z aktivneho web-scanu,
LEN pre domeny v WEBSEC_TARGET_HOSTS (default "orange.sk,www.orange.sk").
Toto skenovanie nerobi scan.py samotny (ten ma pristup len k pasivnym API),
ale samostatny GitHub Actions job, ktory vyprodukuje dva subory:
  ZAP_REPORT_PATH     - JSON report zo ZAP (Baseline alebo Full Scan, rovnaky
                        format, scan.py ich nerozlisuje)
  NUCLEI_REPORT_PATH  - JSONL vystup z `nuclei -jsonl`
scan.py ich len precita a zlucii najdene zaznamy do VLASTNEHO zoznamu
zranitelnosti hosta (ten isty, kde su CVE zo Shodanu a LeakIX), s oznacenim
zdroja "OWASP ZAP" / "Nuclei". Zhoda sa robi podla hostname (nie IP) - zaznam
sa pripoji ku kazdemu hostu, ktoreho meno je v WEBSEC_TARGET_HOSTS.
BEZPECNOSTNA POISTKA: zaznam z WEBSEC sa NIKDY nepripoji k hostu, ktoreho
meno nie je explicitne vo WEBSEC_TARGET_HOSTS - aj keby subory s reportom
omylom obsahovali data o inej domene, tie sa zahodia s upozornenim v logu.
ZAP Baseline je pasivny (len spider + pasivne pravidla, nic neutoci) a da sa
bezpecne spustat automaticky. ZAP Full Scan a niektore Nuclei sablony su
aktivne (posielaju utocne payloady) - v prilozenom workflow su preto v
samostatnom, LEN RUCNE spustitelnom jobe s explicitnym potvrdenim.

Nova zalozka "IP rozsahy (RIPE/BGP)": pre kazdu firmu s nastavenym ASN v companies.json
zobrazi vsetky jej announced prefixy z RIPEstat, s whois detailom a klasifikaciou.
AKTIVNE SKENOVANIE (masscan/nmap) TU NIE JE IMPLEMENTOVANE - vyzaduje pisomne
povolenie vlastnika siete a nehodi sa spustat z verejneho GitHub Actions.

SPATNA VAZBA VYSSEJ KVALITY (confirmed_ranges.json, volitelny subor v koreni repozitara):
zoznam rucne overenych prefixov, ktore MAJU VZDY prednost pred automatickou
heuristikou podla netname/descr. Format (pole objektov):
  [{"company": "orange", "cidr": "80.80.64.0/19", "classification": "own",
    "note": "Core datacentrum Bratislava", "confirmed_by": "meno.priezvisko",
    "confirmed_at": "2026-11-13"}, ...]
- "company" musi zodpovedat "id" z companies.json.
- "classification": "own" (potvrdena firemna infrastruktura) alebo "customer"
  (potvrdeny zakaznicky/CGNAT rozsah, aj keby to heuristika necakala).
- Zaznam moze pokryvat aj siroky CIDR (napr. cely /19) a automaticky sa aplikuje
  na vsetky konkretnejsie prefixy, ktore doň spadaju; ak sa prekryva viac
  zaznamov, pouzije sa ten najspecifickejsi (najdlhsi prefix).
- Subor je volitelny - bez neho sa pouziva len heuristika ako doteraz.
Kazdy prefix v zalozke ma navyse HISTORIU (ako hostia): kedy sa prvykrat objavil,
ci sa zmenila jeho klasifikacia/netname oproti minulemu behu, a zoznam prefixov,
ktore uz nie su announced (ulozene v data/range_history/<firma>.json).

summary = hostname, porty a POCTY zranitelnosti (bez IP a bez CVE ID/popisov).
full    = aj IP, CVE ID, popisy, CPE a historia obsahuje aj CVE ID.
          Pouzi len ak je vystup chraneny/autorizovany - inak summary.

Kazdy host (najdeny cez crt.sh/DNS) ma pole "outside_asn": True ak ma domenu
danej firmy, ale jeho IP NIE JE v ziadnom z prefixov nastavenych ASN tej
firmy (teda bezi mimo jej vlastnej ASN infrastruktury, napr. na cudzom
hostingu alebo CDN). False = IP je v niektorom z prefixov. None = firma
nema v companies.json nastavene ziadne ASN, nedá sa to overit. Tento
priznak je len True/False/None (neprezradzuje IP), preto je viditelny
v OBOCH rezimoch (summary aj full).
"""
import argparse
import ipaddress
import json
import os
import re
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
LEAKIX_CACHE_FILE = Path("data/leakix_cache.json")
HISTORY_DIR = Path("data/history")
COMPANIES_FILE = Path(os.environ.get("COMPANIES_FILE", "companies.json"))
SEV_ORDER = ["critical", "high", "medium", "low", "unknown", "none"]
CACHE_TTL = timedelta(days=7)
CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}")
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


# ---------- RIPE whois detail na prefix (pre zalozku "IP rozsahy") ----------
CUSTOMER_HINTS_RE = re.compile(
    r"(customer|cust[-_]|dsl|adsl|vdsl|gpon|pon[-_]|cgnat|cg-nat|dynamic|dyn[-_]|"
    r"residential|mobile|lte|broadband|pppoe|cable[-_ ]?modem|wifi|retail|home[-_ ]?user)",
    re.IGNORECASE,
)


def fetch_prefix_whois(prefix_str):
    """RIPEstat whois pre jeden konkretny prefix - vrati netname/descr/country/org,
    ak su v RIPE databaze. Bezplatne, bez API kluca."""
    url = "https://stat.ripe.net/data/whois/data.json?resource=" + urllib.parse.quote(prefix_str)
    data = http_json(url, timeout=30, retries=2)
    merged = {}
    for rec in (data or {}).get("data", {}).get("records", []):
        for kv in rec:
            k = (kv.get("key") or "").lower()
            v = kv.get("value")
            if k and v and k not in merged:
                merged[k] = v
    return merged


def heuristic_classify(info):
    """Vseobecna heuristika podla netname/descr - NIE je doveryhodna klasifikacia,
    len napoveda na rozlisenie zakazanickych/CGNAT rozsahov od ostatnych."""
    text = " ".join(str(v) for v in info.values())
    return "customer" if CUSTOMER_HINTS_RE.search(text) else "unknown"


# ---------- rucne potvrdene rozsahy (spatna vazba vyssej kvality ako heuristika) ----------
CONFIRMED_RANGES_FILE = Path(os.environ.get("CONFIRMED_RANGES_FILE", "confirmed_ranges.json"))
RANGE_HISTORY_DIR = Path("data/range_history")
MAX_RANGE_SNAPSHOTS = 50
RANGE_DISAPPEARED_KEEP_DAYS = 60


def load_confirmed_ranges():
    """Nacita confirmed_ranges.json - zoznam rucne overenych zaznamov vo formate:
    [{"company":"orange", "cidr":"80.80.64.0/19", "classification":"own"|"customer",
      "note":"...", "confirmed_by":"meno", "confirmed_at":"2026-11-13"}, ...]
    Subor je volitelny; ak chyba alebo je neplatny, pouzije sa len heuristika."""
    try:
        data = json.loads(CONFIRMED_RANGES_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out = []
    for entry in data if isinstance(data, list) else []:
        try:
            net = ipaddress.ip_network(entry["cidr"], strict=False)
        except (KeyError, ValueError):
            print(f"[!] confirmed_ranges.json: preskakujem neplatny zaznam {entry!r}", file=sys.stderr)
            continue
        out.append({**entry, "_net": net})
    return out


def match_confirmed(prefix_net, confirmed, company_id):
    """Najde najspecifickejsi (najmensi) rucne potvrdeny zaznam, ktory prefix
    obsahuje alebo je s nim totozny. Manualne potvrdenie ma VZDY prednost
    pred heuristikou podla netname/descr."""
    candidates = [e for e in confirmed if e.get("company") == company_id and
                  e["_net"].version == prefix_net.version and
                  (prefix_net == e["_net"] or prefix_net.subnet_of(e["_net"]))]
    if not candidates:
        return None
    return min(candidates, key=lambda e: -e["_net"].prefixlen)  # najspecifickejsi = najdlhsi prefix


def classify_prefix(prefix_net, info, confirmed, company_id):
    """Kombinuje rucne potvrdenie (ak existuje) s heuristikou. Vracia
    (classification, source, note, confirmed_by, confirmed_at)."""
    manual = match_confirmed(prefix_net, confirmed, company_id)
    if manual:
        return (manual.get("classification", "own"), "manual", manual.get("note", ""),
                manual.get("confirmed_by", ""), manual.get("confirmed_at", ""))
    return (heuristic_classify(info), "heuristic", "", "", "")


# ---------- historia klasifikacie prefixov (rovnaky princip ako historia hostov) ----------
def range_snapshot(row):
    return {"date": now_iso(), "classification": row["classification"], "source": row["source"],
            "netname": row["netname"], "descr": row["descr"], "country": row["country"], "org": row["org"]}


def range_snap_changed(prev, cur):
    if prev is None:
        return True
    keys = ("classification", "source", "netname", "descr", "country", "org")
    return any(prev.get(k) != cur.get(k) for k in keys)


def diff_range_snaps(prev, cur):
    if prev is None:
        return {"new_range": True}
    changes = {}
    if cur["classification"] != prev.get("classification"):
        changes["classification_from"] = prev.get("classification")
        changes["classification_to"] = cur["classification"]
    if cur["netname"] != prev.get("netname"):
        changes["netname_from"] = prev.get("netname")
        changes["netname_to"] = cur["netname"]
    return changes


def apply_range_history(cid, rows):
    """Analogicke k apply_history() pre hostov: kazdemu prefixu doplni
    first_seen/is_new/changes/history a vrati zoznam prefixov, ktore predtym
    boli announced a teraz uz nie su (zmiznute/reassignovane rozsahy)."""
    path = RANGE_HISTORY_DIR / f"{cid}.json"
    hist = load_json(path, {})
    seen = set()
    for row in rows:
        key = row["cidr"]
        seen.add(key)
        entry = hist.setdefault(key, {"first_seen": now_iso(), "last_seen": None, "snapshots": []})
        entry["last_seen"] = now_iso()
        prev = entry["snapshots"][-1] if entry["snapshots"] else None
        cur = range_snapshot(row)
        row["is_new"] = prev is None
        row["first_seen"] = entry["first_seen"]
        row["changes"] = diff_range_snaps(prev, cur)
        if range_snap_changed(prev, cur):
            entry["snapshots"].append(cur)
            entry["snapshots"] = entry["snapshots"][-MAX_RANGE_SNAPSHOTS:]
        row["history"] = entry["snapshots"][-20:][::-1]

    cutoff = datetime.now(timezone.utc) - timedelta(days=RANGE_DISAPPEARED_KEEP_DAYS)
    disappeared = []
    for key, entry in hist.items():
        if key in seen:
            continue
        try:
            last_seen = datetime.fromisoformat(entry["last_seen"])
        except (KeyError, ValueError, TypeError):
            continue
        if last_seen < cutoff:
            continue
        last_snap = entry["snapshots"][-1] if entry["snapshots"] else {}
        disappeared.append({"cidr": key, "first_seen": entry.get("first_seen"),
                            "last_seen": entry.get("last_seen"),
                            "last_classification": last_snap.get("classification", "unknown")})
    disappeared.sort(key=lambda d: d["last_seen"], reverse=True)
    save_json(path, hist)
    return disappeared[:50]


def build_ranges_section(companies, max_prefix_details):
    """Pre kazdu firmu s nastavenym ASN stiahne vsetky announced prefixy (RIPEstat)
    a pre prvych max_prefix_details z nich aj whois detail (netname/descr/country).
    Klasifikacia: rucne potvrdenie z confirmed_ranges.json ma VZDY prednost pred
    heuristikou podla netname/descr. Kazdy prefix ma aj historiu zmien a oznacenie
    noveho/zmeneneho zaznamu, rovnako ako hostia v ostatnych zalozkach. Cisto
    pasivne, bez API kluca, legalne pre kohokolvek - toto je krok "zistit, co
    patri firme na urovni IP"."""
    confirmed = load_confirmed_ranges()
    out = {}
    for c in companies:
        asns = c.get("asns", [])
        prefixes = []
        for a in asns:
            prefixes += get_prefixes(a)
        prefixes = sorted(set(prefixes), key=lambda p: (p.version, p.num_addresses))
        rows = []
        for p in prefixes[:max_prefix_details]:
            try:
                info = fetch_prefix_whois(str(p))
            except Exception as e:  # noqa: BLE001
                print(f"[!] RIPE whois {p}: {e}", file=sys.stderr)
                info = {}
            cls, source, note, confirmed_by, confirmed_at = classify_prefix(p, info, confirmed, c["id"])
            rows.append({
                "cidr": str(p), "size": p.num_addresses,
                "netname": info.get("netname", ""), "descr": info.get("descr", ""),
                "country": info.get("country", ""),
                "org": info.get("org-name") or info.get("org", ""),
                "classification": cls, "source": source, "note": note,
                "confirmed_by": confirmed_by, "confirmed_at": confirmed_at,
            })
            time.sleep(0.3)
        disappeared = apply_range_history(c["id"], rows)
        new_count = sum(1 for r in rows if r.get("is_new"))
        changed_count = sum(1 for r in rows if r.get("changes") and not r.get("is_new"))
        out[c["id"]] = {
            "name": c["name"], "asns": asns, "prefix_count": len(prefixes),
            "shown": len(rows), "skipped": max(0, len(prefixes) - max_prefix_details),
            "rows": rows, "generated": now_iso(), "disappeared": disappeared,
            "changes_summary": {"new": new_count, "changed": changed_count, "disappeared": len(disappeared)},
        }
        if asns:
            manual_count = sum(1 for r in rows if r["source"] == "manual")
            print(f"[+] {c['id']}: {len(prefixes)} prefixov z RIPE, whois detail pre {len(rows)} "
                  f"({manual_count} rucne potvrdenych), novych {new_count}, zmenenych {changed_count}, "
                  f"zmiznutych {len(disappeared)}")
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


# ---------- LeakIX: doplnkove CVE z host lookup ----------
def normalize_leakix_cves(host_data):
    """LeakIX vracia {"Services":[...], "Leaks":[...]}, kazda polozka moze mat
    pole 'tags' s hodnotami ako 'cve-2021-26084' a textovy popis v 'summary'.
    Pre istotu sa navyse prejde cela odpoved regexom, ak by CVE bolo inde."""
    found = {}
    events = []
    if isinstance(host_data, dict):
        events += host_data.get("Services") or []
        events += host_data.get("Leaks") or []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        summary = ev.get("summary") or ev.get("Summary") or ""
        for tag in (ev.get("tags") or []):
            if not isinstance(tag, str):
                continue
            cid = tag.upper()
            if CVE_ID_RE.fullmatch(cid):
                entry = found.setdefault(cid, {"summary": ""})
                if summary and not entry["summary"]:
                    entry["summary"] = short(str(summary))
    for cid in CVE_ID_RE.findall(json.dumps(host_data or {})):
        found.setdefault(cid.upper(), {"summary": ""})
    return [{"id": cid, "cvss": None, "severity": "unknown", "kev": False,
            "summary": info["summary"], "source": "LeakIX"} for cid, info in found.items()]


def fetch_leakix_host(ip, api_key):
    url = f"https://leakix.net/host/{ip}"
    data = http_json(url, timeout=30, retries=2, headers={"api-key": api_key, "Accept": "application/json"})
    return normalize_leakix_cves(data)


def _leakix_fresh(entry):
    try:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(entry["fetched"])
        return age < CACHE_TTL and "cves" in entry
    except (KeyError, ValueError, TypeError):
        return False


def enrich_leakix(ips, api_key, max_calls):
    """Vrati {ip: [cve, ...]}. Cachuje na CACHE_TTL a dodrzuje max_calls za beh,
    aby sa neminul bezplatny kredit."""
    cache = load_json(LEAKIX_CACHE_FILE, {})
    if not api_key:
        print("[!] LEAKIX_API_KEY nie je nastaveny, LeakIX obohatenie sa preskakuje "
              "(pouzivam predoslu cache, ak existuje)", file=sys.stderr)
        return {ip: v.get("cves", []) for ip, v in cache.items()}

    todo = [ip for ip in sorted(ips, key=ipaddress.ip_address) if ip not in cache or not _leakix_fresh(cache[ip])]
    print(f"[*] LeakIX: {len(ips)} IP celkovo, {len(todo)} treba overit (limit tohto behu: {max_calls})")
    calls = 0
    for ip in todo:
        if calls >= max_calls:
            print(f"[!] LeakIX: dosiahnuty limit {max_calls} volani na tento beh, zvysok preskakujem "
                  "(dobehnu nasledujuci den)", file=sys.stderr)
            break
        try:
            cves = fetch_leakix_host(ip, api_key)
            cache[ip] = {"fetched": now_iso(), "cves": cves}
        except Exception as e:  # noqa: BLE001
            print(f"[!] LeakIX {ip}: {e}", file=sys.stderr)
        calls += 1
        time.sleep(0.3)
    save_json(LEAKIX_CACHE_FILE, cache)
    print(f"[+] LeakIX: vykonanych {calls} volani, cache ma {len(cache)} IP")
    return {ip: v.get("cves", []) for ip, v in cache.items()}


# ---------- WEBSEC: ZAP / Nuclei reporty (len pre explicitne povolene hostname) ----------
ZAP_RISK_TO_SEV = {"high": "high", "medium": "medium", "low": "low", "informational": "unknown"}
STRIP_TAGS_RE = re.compile(r"<[^>]+>")


def parse_zap_report(path):
    """ZAP JSON report: {"site":[{"@name": "https://orange.sk", "alerts":[...]}]}.
    Vrati {hostname(lower): [finding, ...]}. Kazdy alert sa priradi k hostu
    podla hostname site URL, v ktorom bol najdeny."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        eprint_once(f"[!] ZAP report {path}: {e}")
        return {}
    out = {}
    for site in data.get("site", []):
        host = (urllib.parse.urlparse(site.get("@name", "")).hostname or "").lower()
        if not host:
            continue
        for alert in site.get("alerts", []):
            riskdesc = (alert.get("riskdesc") or "").split(" ")[0].lower()
            sev = ZAP_RISK_TO_SEV.get(riskdesc, "unknown")
            desc = STRIP_TAGS_RE.sub(" ", alert.get("desc", "") or alert.get("name", ""))
            finding = {
                "id": "ZAP-" + str(alert.get("pluginid", alert.get("alertRef", "?"))),
                "cvss": None, "severity": sev, "kev": False,
                "summary": short(f"{alert.get('name','')}: {desc}"), "source": "OWASP ZAP",
            }
            out.setdefault(host, []).append(finding)
    return out


def parse_nuclei_report(path):
    """Nuclei JSONL (`nuclei -jsonl`): jeden JSON objekt na riadok, s poľami
    'host', 'template-id' a 'info' (name/severity/description/classification).
    Vrati {hostname(lower): [finding, ...]}."""
    out = {}
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as e:
        eprint_once(f"[!] Nuclei report {path}: {e}")
        return {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        raw_host = rec.get("host") or rec.get("matched-at") or ""
        host = (urllib.parse.urlparse(raw_host).hostname or raw_host).lower().strip("/")
        if not host:
            continue
        info = rec.get("info", {}) or {}
        classification = info.get("classification") or {}
        cve_ids = classification.get("cve-id") or []
        cid = cve_ids[0].upper() if cve_ids and CVE_ID_RE.fullmatch(str(cve_ids[0]).upper()) else \
            "NUCLEI-" + str(rec.get("template-id", "?"))
        sev = (info.get("severity") or "unknown").lower()
        sev = "unknown" if sev in ("info", "informational", "") else sev
        if sev not in SEV_ORDER:
            sev = "unknown"
        cvss = classification.get("cvss-score")
        cvss = cvss if isinstance(cvss, (int, float)) else None
        finding = {
            "id": cid, "cvss": cvss, "severity": sev if cvss is None else severity(cvss),
            "kev": False, "summary": short(info.get("description") or info.get("name", "")),
            "source": "Nuclei",
        }
        out.setdefault(host, []).append(finding)
    return out


_EPRINT_SEEN = set()


def eprint_once(msg):
    if msg not in _EPRINT_SEEN:
        _EPRINT_SEEN.add(msg)
        print(msg, file=sys.stderr)


def build_websec_map(zap_paths, nuclei_paths, target_hosts):
    """Nacita jeden alebo viac ZAP/Nuclei reportov (ciarkou oddelene cesty -
    napr. samostatny report pre orange.sk a samostatny pre www.orange.sk,
    kedze jeden host moze spojenie resetovat a iny nie) a vrati
    {hostname: [finding,...]}. OBMEDZENE LEN na target_hosts - vsetko
    ostatne sa zahodi s upozornenim, aj keby to subory s reportom
    obsahovali (bezpecnostna poistka proti omylom rozsirenemu scope)."""
    allowed = {h.strip().lower() for h in target_hosts if h.strip()}
    merged = {}
    for raw_paths, parser, label in ((zap_paths, parse_zap_report, "ZAP"), (nuclei_paths, parse_nuclei_report, "Nuclei")):
        if not raw_paths:
            continue
        for path in [p.strip() for p in raw_paths.split(",") if p.strip()]:
            if not Path(path).exists():
                print(f"[!] {label}: subor {path} neexistuje, preskakujem (mozno sa pre tento host "
                      f"nepodarilo sken dokoncit - napr. connection reset)", file=sys.stderr)
                continue
            found = parser(path)
            used = 0
            for host, findings in found.items():
                if host not in allowed:
                    print(f"[!] {label}: host '{host}' nie je v WEBSEC_TARGET_HOSTS, "
                          f"{len(findings)} zaznamov zahadzujem (bezpecnostna poistka)", file=sys.stderr)
                    continue
                merged.setdefault(host, []).extend(findings)
                used += len(findings)
            print(f"[+] {label}: {path} -> {sum(len(v) for v in found.values())} zaznamov, "
                  f"{used} pouzitelnych pre povolene hosty")
    return merged


def merge_cves(shodan_cves, extra_cves):
    """Zluci CVE z dvoch zdrojov do jedneho zoznamu, kazda s poľom 'source'.
    Ak CVE nahlasia obidva zdroje, source sa spoji (napr. 'Shodan + LeakIX')
    a doplnia sa chybajuce udaje (prednost ma hodnota, ktora uz existuje)."""
    by_id = {}
    for c in shodan_cves:
        by_id[c["id"]] = {**c, "source": "Shodan"}
    for c in extra_cves:
        if c["id"] in by_id:
            existing = by_id[c["id"]]
            if c["source"] not in existing["source"]:
                existing["source"] = existing["source"] + " + " + c["source"]
            if existing.get("cvss") is None and c.get("cvss") is not None:
                existing["cvss"] = c["cvss"]
                existing["severity"] = c["severity"]
            if not existing.get("summary") and c.get("summary"):
                existing["summary"] = c["summary"]
        else:
            by_id[c["id"]] = c
    return list(by_id.values())


# ---------- zber pre jednu firmu ----------
def collect(company, args, memo, dns_merge=None):
    """dns_merge: {domena: [normalizovane DNS zaznamy s poľom 'ips']} - hosty najdene cez
    DNSDumpster sa pridaju do host_ips PRED dopytom na InternetDB, takze dostanu rovnake
    porty/CVE detaily ako hosty najdene cez crt.sh."""
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

    dns_added = 0
    for d in company.get("domains", []):
        for rec in (dns_merge or {}).get(d, []) or []:
            host = rec.get("host")
            if not host:
                continue
            for ip in rec.get("ips", []) or []:
                host_ips.setdefault(ip, set()).add(host)
                dns_added += 1
    if dns_added:
        print(f"    dnsdumpster: {dns_added} zaznamov host-IP zlucenych do zoznamu")

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


def build_assets(raw, host_ips, prefixes, cache, mode, leakix_map=None, websec_map=None):
    def in_prefix(ip):
        addr = ipaddress.ip_address(ip)
        return any(addr in p for p in prefixes if p.version == addr.version)

    leakix_map = leakix_map or {}
    websec_map = websec_map or {}
    assets = []
    for ip, d in raw.items():
        shodan_cves = []
        for cid in sorted(d.get("vulns", [])):
            info = cache.get(cid, {})
            cvss = info.get("cvss")
            shodan_cves.append({"id": cid, "cvss": cvss, "severity": severity(cvss),
                                "kev": bool(info.get("kev")), "epss": info.get("epss"),
                                "summary": info.get("summary", "")})
        cves = merge_cves(shodan_cves, leakix_map.get(ip, []))
        websec_findings = [f for host in host_ips[ip] for f in websec_map.get(host.lower(), [])]
        if websec_findings:
            cves = merge_cves(cves, websec_findings)
        counts = {s: sum(1 for c in cves if c["severity"] == s)
                  for s in ("critical", "high", "medium", "low", "unknown")}
        scores = [c["cvss"] for c in cves if c["cvss"] is not None]
        # outside_asn: True = host MA domenu firmy, ale jeho IP NIE JE v ziadnom
        # z prefixov nastavenych ASN danej firmy (napr. subdomena bezi na cudzom
        # hostingu/CDN, nie na vlastnej infrastrukture). None = firma nema v
        # companies.json nastavene ASN, takze sa to neda overit. Je to len
        # True/False/None, nie IP adresa, preto sa zobrazuje v OBOCH rezimoch.
        outside_asn = (not in_prefix(ip)) if prefixes else None
        rec = {
            "names": sorted(host_ips[ip]),
            "ports": sorted(d.get("ports", [])),
            "tags": d.get("tags", []),
            "counts": counts,
            "cve_count": len(cves),
            "kev_count": sum(1 for c in cves if c["kev"]),
            "max_severity": next((s for s in SEV_ORDER[:5] if counts.get(s)), "none"),
            "max_cvss": max(scores) if scores else None,
            "outside_asn": outside_asn,
        }
        if mode == "full":
            rec.update({"ip": ip, "cpes": d.get("cpes", []), "cves": cves})
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
                ip_list = [i["ip"] for i in ips if i["ip"]]
                records.append({
                    "type": rtype.upper(),
                    "host": entry.get("host", ""),
                    "value": ", ".join(ip_list) or entry.get("target", ""),
                    "asn": ", ".join(sorted({i["asn_name"] or i["asn"] for i in ips if (i["asn_name"] or i["asn"])})),
                    "ips": ip_list,  # pouzite len interne na zlucenie s InternetDB/Shodan udajmi
                })
            elif isinstance(entry, dict):
                records.append({"type": rtype.upper(), "host": entry.get("host", entry.get("name", "")),
                                "value": short(json.dumps(entry, ensure_ascii=False), 200), "asn": "", "ips": []})
            else:
                records.append({"type": rtype.upper(), "host": "", "value": str(entry), "asn": "", "ips": []})
    records.sort(key=lambda r: (r["type"], r["host"], r["value"]))
    return records


def fetch_dns_records(domain, api_key):
    url = f"https://api.dnsdumpster.com/domain/{urllib.parse.quote(domain)}"
    data = http_json(url, timeout=60, retries=2, headers={"X-API-Key": api_key})
    return normalize_dnsdumpster(data)


def fetch_all_dns(companies, api_key, previous_dns):
    """Stiahne DNS zaznamy pre vsetky domeny (raz za domenu) a vrati dve veci:
    - dns_domains_out: na zobrazenie v zalozke "Vsetky DNS zaznamy"
    - dns_merge: {domena: zaznamy} na zlucenie do host_ips jednotlivych firiem,
      aby hosty najdene cez dnsdumpster dostali rovnake Shodan detaily ako ostatne."""
    domains = sorted({d for c in companies for d in c.get("domains", [])})
    dns_domains_out, dns_merge = {}, {}
    if not api_key:
        print("[!] DNSDUMPSTER_API_KEY nie je nastaveny, zalozka DNS zaznamov sa nedopocita "
              "(ponechavam predosle data, ak existuju)", file=sys.stderr)
        for d in domains:
            prev = previous_dns.get(d) or {"generated": None, "stale": True, "records": [], "count": 0}
            dns_domains_out[d] = prev
            dns_merge[d] = prev.get("records", [])
        return dns_domains_out, dns_merge
    for d in domains:
        try:
            records = fetch_dns_records(d, api_key)
            dns_domains_out[d] = {"generated": now_iso(), "stale": False, "records": records, "count": len(records)}
            dns_merge[d] = records
            print(f"[+] dnsdumpster {d}: {len(records)} zaznamov")
        except Exception as e:  # noqa: BLE001
            print(f"[!] dnsdumpster {d}: {e}", file=sys.stderr)
            if d in previous_dns:
                old = dict(previous_dns[d]); old["stale"] = True
                dns_domains_out[d] = old
                dns_merge[d] = old.get("records", [])
            else:
                dns_domains_out[d] = {"generated": None, "stale": True, "records": [], "count": 0, "error": str(e)}
                dns_merge[d] = []
        time.sleep(1.5)  # slusne tempo voci API
    return dns_domains_out, dns_merge


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

    prev_full = load_json(OUT_FILE, {})
    prev_dns = (prev_full.get("dns") or {}).get("domains", {})
    print("[*] DNSDumpster: stahovanie DNS zaznamov")
    dns_domains, dns_merge = fetch_all_dns(companies, env("DNSDUMPSTER_API_KEY"), prev_dns)

    memo, collected = {}, {}
    for c in companies:
        print(f"[*] {c['name']} ({c['id']})")
        try:
            collected[c["id"]] = collect(c, args, memo, dns_merge)
        except Exception as e:  # noqa: BLE001
            print(f"[!] {c['id']} zlyhalo: {e}", file=sys.stderr)

    all_cves = {v for _, _, raw in collected.values() for d in raw.values() for v in d.get("vulns", [])}
    cache = enrich_cves(all_cves)

    all_ips = {ip for _, _, raw in collected.values() for ip in raw}
    leakix_max_calls = int(env("LEAKIX_MAX_CALLS") or 100)
    leakix_map = enrich_leakix(all_ips, env("LEAKIX_API_KEY"), leakix_max_calls)

    websec_targets = (env("WEBSEC_TARGET_HOSTS") or "orange.sk,www.orange.sk").split(",")
    websec_map = build_websec_map(env("ZAP_REPORT_PATH"), env("NUCLEI_REPORT_PATH"), websec_targets)

    out_companies = []
    for c in companies:
        got = collected.get(c["id"])
        if got and (got[0] or got[2]):
            assets = build_assets(got[2], got[0], got[1], cache, args.mode, leakix_map, websec_map)
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

    has_asns = any(c.get("asns") for c in companies)
    if not any(c["assets"] for c in out_companies) and not env("DNSDUMPSTER_API_KEY") and not has_asns:
        sys.exit("Ziadne data pre ziadnu firmu. Neprepisujem existujuci vystup.")

    max_prefix_details = int(env("MAX_PREFIX_DETAILS") or 100)
    ranges = build_ranges_section(companies, max_prefix_details)

    save_json(OUT_FILE, {
        "generated": now_iso(), "mode": args.mode, "companies": out_companies,
        "dns": {"generated": now_iso(), "domains": dns_domains},
        "ranges": {"generated": now_iso(), "companies": ranges},
    })
    print(f"[+] Ulozene -> {OUT_FILE} (rezim {args.mode})")


if __name__ == "__main__":
    main()
