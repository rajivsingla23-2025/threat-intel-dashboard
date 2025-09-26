"""
Agent toolbelt for the Threat Intel Dashboard.
- Pure-requests (no vendor SDKs) to keep it portable on Streamlit Cloud.
- Safe defaults (rate limits, caching, allowlists, timeouts).
"""

from __future__ import annotations
import os, re, json, time, hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Tuple
import requests

# ---------- Tunables ----------
HTTP_TIMEOUT = 15
USER_AGENT = "TI-Dashboard-Agent/1.0"
ALLOWED_HOSTS = {
    "services.nvd.nist.gov", "api.first.org", "www.cisa.gov",
    "bazaar.abuse.ch", "urlhaus.abuse.ch", "hooks.slack.com"
}
CACHE_TTL_SECONDS = 60 * 30  # 30 min
DRY_RUN = os.getenv("AGENT_DRY_RUN", "false").lower() == "true"
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", "")
JIRA_BASE = os.getenv("JIRA_BASE_URL", "")        # e.g. https://yourco.atlassian.net
JIRA_USER = os.getenv("JIRA_USER_EMAIL", "")
JIRA_TOKEN = os.getenv("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY", "SEC")

# Simple in-memory cache (sufficient for Streamlit single-process)
_cache: Dict[str, Tuple[float, Any]] = {}

def _cache_get(key: str):
    v = _cache.get(key)
    if not v: return None
    ts, data = v
    if time.time() - ts > CACHE_TTL_SECONDS:
        _cache.pop(key, None)
        return None
    return data

def _cache_set(key: str, data: Any):
    _cache[key] = (time.time(), data)

def _allowlisted(url: str) -> bool:
    try:
        host = requests.utils.urlparse(url).hostname or ""
        return host in ALLOWED_HOSTS
    except Exception:
        return False

def _get_json(url: str, params=None, headers=None):
    if not _allowlisted(url):
        raise ValueError(f"Host not allow-listed: {url}")
    key = "GET:" + url + "|" + json.dumps(params or {}, sort_keys=True)
    hit = _cache_get(key)
    if hit is not None:
        return hit
    hdrs = {"User-Agent": USER_AGENT}
    if headers: hdrs.update(headers)
    r = requests.get(url, params=params, headers=hdrs, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    data = r.json()
    _cache_set(key, data)
    return data

def _post_json(url: str, data=None, headers=None):
    if not _allowlisted(url):
        raise ValueError(f"Host not allow-listed: {url}")
    hdrs = {"User-Agent": USER_AGENT}
    if headers: hdrs.update(headers)
    r = requests.post(url, data=data, headers=hdrs, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    return r.json()

# ------------------- Feed helpers (from your app cache) -------------------
def fetch_feed_from_df(df, query: Optional[str]=None, hours: int=24) -> List[Dict[str, Any]]:
    """Filter the existing dashboard dataframe (already aggregated) by time window + keyword."""
    if df is None or df.empty:
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    # Ensure 'Published' is datetime (your app already does this)
    fdf = df[df["Published"] >= cutoff]
    if query:
        fdf = fdf[fdf["Title"].str.contains(query, case=False, na=False)]
    out = fdf[["Published", "Source", "Title", "Link"]].sort_values("Published", ascending=False)
    return out.to_dict(orient="records")

# ------------------- CVE enrichment -------------------
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

def extract_cves(text: str) -> List[str]:
    return list(dict.fromkeys(_CVE_RE.findall(text or "")))  # unique, keep order

def get_cve_details(cve_id: str) -> Dict[str, Any]:
    """NVD v1.0 single-CVE endpoint (no API key required for low volume)."""
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    data = _get_json(url)
    try:
        item = data["result"]["CVE_Items"][0]
        desc = item["cve"]["description"]["description_data"][0]["value"]
        metrics = item.get("impact", {})
        cvss = None
        vector = None
        if "baseMetricV3" in metrics:
            cvss = metrics["baseMetricV3"]["cvssV3"]["baseScore"]
            vector = metrics["baseMetricV3"]["cvssV3"]["vectorString"]
        elif "baseMetricV2" in metrics:
            cvss = metrics["baseMetricV2"]["cvssV2"]["baseScore"]
            vector = metrics["baseMetricV2"]["cvssV2"]["vectorString"]
        pub = item["publishedDate"]
        refs = [r["url"] for r in item["cve"]["references"]["reference_data"]][:8]
        return {"cve": cve_id, "cvss": cvss, "vector": vector, "description": desc, "published": pub, "references": refs}
    except Exception:
        return {"cve": cve_id, "error": "NVD parse error"}

def get_epss(cve_id: str) -> Dict[str, Any]:
    """FIRST EPSS score."""
    url = "https://api.first.org/data/v1/epss"
    data = _get_json(url, params={"cve": cve_id})
    rows = data.get("data", [])
    if not rows: return {"cve": cve_id, "epss": None}
    row = rows[0]
    return {"cve": cve_id, "epss": float(row.get("epss", 0.0)), "percentile": float(row.get("percentile", 0.0))}

def is_in_cisa_kev(cve_id: str) -> Dict[str, Any]:
    """Check CISA Known Exploited Vulnerabilities list (JSON)."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev = _get_json(url)
    for v in kev.get("vulnerabilities", []):
        if v.get("cveID") == cve_id:
            return {"cve": cve_id, "in_kev": True, "date_added": v.get("dateAdded"), "due_date": v.get("dueDate")}
    return {"cve": cve_id, "in_kev": False}

# ------------------- MalwareBazaar enrichment -------------------
def mb_enrich_sha256(sha256: str) -> Dict[str, Any]:
    url = "https://bazaar.abuse.ch/api/v1/"
    res = _post_json(url, data={"query": "get_info", "hash": sha256})
    if res.get("query_status") != "ok": return {"sha256": sha256, "found": False}
    d = res["data"][0]
    return {
        "sha256": sha256,
        "found": True,
        "file_type": d.get("file_type"),
        "signature": d.get("signature"),
        "first_seen": d.get("first_seen"),
        "vendor_intel": d.get("vendor_intel", {})
    }

# ------------------- Notifications / Tickets -------------------
def notify_slack(text: str, channel_hint: str="#threat-intel") -> Dict[str, Any]:
    if not SLACK_WEBHOOK:
        return {"ok": False, "error": "No webhook configured"}
    if DRY_RUN:
        return {"ok": True, "dry_run": True, "text": text}
    headers = {"Content-Type": "application/json"}
    payload = {"text": text}
    r = requests.post(SLACK_WEBHOOK, headers=headers, data=json.dumps(payload), timeout=HTTP_TIMEOUT)
    try:
        r.raise_for_status()
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e), "status": r.status_code, "body": r.text[:300]}

def create_jira(summary: str, description: str, severity: str="Medium") -> Dict[str, Any]:
    if not (JIRA_BASE and JIRA_USER and JIRA_TOKEN):
        return {"ok": False, "error": "Jira creds missing"}
    if DRY_RUN:
        return {"ok": True, "dry_run": True, "summary": summary}
    url = f"{JIRA_BASE}/rest/api/3/issue"
    headers = {"Content-Type": "application/json"}
    auth = (JIRA_USER, JIRA_TOKEN)
    data = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": summary[:240],
            "description": description[:30000],
            "issuetype": {"name": "Task"},
            "priority": {"name": severity}
        }
    }
    r = requests.post(url, headers=headers, auth=auth, data=json.dumps(data), timeout=HTTP_TIMEOUT)
    try:
        r.raise_for_status()
        return {"ok": True, "key": r.json().get("key")}
    except Exception as e:
        return {"ok": False, "error": str(e), "status": r.status_code, "body": r.text[:300]}
