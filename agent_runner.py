"""
Lightweight agent runner.
- If OPENAI_API_KEY is set, uses LLM for planning/summarizing via tool calls.
- Else, uses heuristic planner (rules) and templated summary.
"""

from __future__ import annotations
import os, re
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
import pandas as pd

from agent_tools import (
    fetch_feed_from_df, extract_cves, get_cve_details, get_epss, is_in_cisa_kev,
    mb_enrich_sha256, notify_slack, create_jira
)

USE_LLM = bool(os.getenv("OPENAI_API_KEY"))
# Optional: pip install openai>=1.50
if USE_LLM:
    from openai import OpenAI
    oai = OpenAI()

SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

def _heuristic_plan(query: str) -> dict:
    q = query.lower()
    plan = {
        "need_feeds": True,
        "hours": 24,  # default
        "keywords": [],
        "cves": [],
        "hashes": [],
        "actions": []
    }

    # --- Time window parsing ---
    # Regex to capture "number + unit" like "72 hours", "5 days", "2 weeks", "1 month"
    m = re.search(r"(\d+)\s*(hour|hours|day|days|week|weeks|month|months)", q)
    if m:
        num = int(m.group(1))
        unit = m.group(2)
        if "hour" in unit:
            plan["hours"] = num
        elif "day" in unit:
            plan["hours"] = num * 24
        elif "week" in unit:
            plan["hours"] = num * 7 * 24
        elif "month" in unit:
            plan["hours"] = num * 30 * 24
    else:
        # --- Fallbacks only if no number is given ---
        if "week" in q:
            plan["hours"] = 7 * 24
        elif "month" in q:
            plan["hours"] = 30 * 24

    # --- Keywords (basic) ---
    words = [w.strip(",.") for w in query.split() if len(w) > 3 and not w.startswith("cve-")]
    plan["keywords"] = words[:5]

    # --- CVEs and hashes extraction ---
    from agent_tools import extract_cves
    plan["cves"] = extract_cves(query)

    SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
    plan["hashes"] = SHA256_RE.findall(query)

    # --- Action hints ---
    if "notify" in q or "slack" in q:
        plan["actions"].append("notify_slack")
    if "ticket" in q or "jira" in q or "create issue" in q:
        plan["actions"].append("create_jira")

    return plan

def _summarize_heuristic(query, feeds, cve_details, kev_hits, epss_scores, hash_enrich):
    lines = [f"### Intel summary for: **{query}**",
             f"- Time window: last {feeds.get('hours', 24)} hours",
             f"- Items matched: {len(feeds.get('items', []))}"]
    if feeds.get("items"):
        lines.append("\n**Top items:**")
        for it in feeds["items"][:5]:
            lines.append(f"- {it['Published'].strftime('%Y-%m-%d %H:%M')} | {it['Source']}: [{it['Title']}]({it['Link']})")
    if cve_details:
        lines.append("\n**CVE details:**")
        for c in cve_details:
            cvss = c.get("cvss")
            lines.append(f"- {c['cve']} | CVSS: {cvss} | {c.get('description','')[:140]}...")
    if kev_hits:
        kev_list = [k['cve'] for k in kev_hits if k.get("in_kev")]
        if kev_list:
            lines.append(f"\n**CISA KEV:** {', '.join(kev_list)} (known exploited)")
    if epss_scores:
        top = sorted(epss_scores, key=lambda x: x.get("epss", 0), reverse=True)[:5]
        if top:
            lines.append("\n**Top EPSS CVEs:** " + ", ".join([f"{t['cve']} ({t['epss']:.2f})" for t in top if t.get('epss') is not None]))
    if hash_enrich:
        lines.append("\n**Hash enrichments:**")
        for h in hash_enrich:
            if h.get("found"):
                lines.append(f"- {h['sha256']} | {h.get('file_type')} | {h.get('signature')}")
    return "\n".join(lines)

def run_agent(query: str, df: Optional[pd.DataFrame], approve: bool=False) -> Dict[str, Any]:
    plan = _heuristic_plan(query)
    # 1) Feeds
    items = fetch_feed_from_df(df, " ".join(plan["keywords"]) if plan["keywords"] else None, plan["hours"])
    feed_pack = {"hours": plan["hours"], "items": items}

    # 2) CVEs
    cve_out, kev_out, epss_out = [], [], []
    for c in plan["cves"]:
        cve_out.append(get_cve_details(c))
        kev_out.append(is_in_cisa_kev(c))
        epss_out.append(get_epss(c))

    # 3) Hashes
    hash_out = [mb_enrich_sha256(h) for h in plan["hashes"][:5]]

    # 4) Compose summary (LLM optional)
    if USE_LLM:
        # Short, cost-aware prompt; include only metadata (no large bodies)
        prompt = f"""You are a SOC intel assistant. Summarize these findings for: "{query}".
- Time window: {plan['hours']} hours.
- Feed hits: {len(items)}.
- CVEs: {plan['cves']}.
- KEV: {[k for k in kev_out if k.get('in_kev')]}.
- EPSS: {epss_out[:5]}.
- Hashes: {hash_out[:5]}.
Produce: 1) Executive summary (3 bullets). 2) Top items with links (<=5). 3) Recommended actions."""
        comp = oai.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[{"role":"system","content":"Be precise, concise, and action oriented."},
                      {"role":"user","content": prompt}],
            temperature=0.2,
        )
        summary_md = comp.choices[0].message.content
    else:
        summary_md = _summarize_heuristic(query, feed_pack, cve_out, kev_out, epss_out, hash_out)

    # 5) Proposed actions
    actions = []
    high_cves = [c for c in cve_out if (c.get("cvss") or 0) >= 8.5]
    kev_cves = [k["cve"] for k in kev_out if k.get("in_kev")]
    if high_cves or kev_cves:
        actions.append({
            "type": "notify_slack",
            "title": "Notify on high/KEV CVEs",
            "params": {"text": f"High/KEV CVEs found for query '{query}': "
                               f"{[c['cve'] for c in high_cves]} + KEV={kev_cves}"}
        })
        actions.append({
            "type": "create_jira",
            "title": "Create remediation ticket",
            "params": {"summary": f"[Intel] Review high/KEV CVEs – {', '.join([c['cve'] for c in high_cves]+kev_cves)[:180]}",
                       "description": summary_md, "severity":"High" if high_cves or kev_cves else "Medium"}
        })

    executed = []
    if approve:
        for a in actions:
            if a["type"] == "notify_slack":
                executed.append({"action": a, "result": notify_slack(**a["params"])})
            elif a["type"] == "create_jira":
                executed.append({"action": a, "result": create_jira(**a["params"])})
    audit = {
        "plan": plan,
        "feed_items_preview": items[:5],
        "cve_details_preview": cve_out[:3],
        "kev_preview": kev_out[:3],
        "epss_preview": epss_out[:3],
        "hash_enrich_preview": hash_out[:3],
        "approved": approve
    }
    return {"summary_md": summary_md, "actions": actions, "executed": executed, "audit": audit}

