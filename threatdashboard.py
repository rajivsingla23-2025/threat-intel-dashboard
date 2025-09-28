import streamlit as st
import feedparser
import requests
import pandas as pd
from datetime import datetime
from dateutil import parser
import re
from streamlit_autorefresh import st_autorefresh
from agent_runner import run_agent


# -----------------------------
# FEEDS
# -----------------------------
feeds = {
    "Cisco Talos": "https://blog.talosintelligence.com/feed/",
    "MSRC": "https://msrc.microsoft.com/update-guide/rss",
    "Palo Alto Unit42": "https://unit42.paloaltonetworks.com/feed/",
    "CrowdStrike": "https://www.crowdstrike.com/blog/feed/",
    "Mandiant": "https://www.mandiant.com/resources/blog/rss.xml",
    "Kaspersky": "https://securelist.com/feed/",
    "ZDI": "https://www.zerodayinitiative.com/rss/upcoming/"
}

malware_bazaar_api = "https://mb-api.abuse.ch/api/v1/"

# -----------------------------
# THREAT ACTOR LIST (expandable)
# -----------------------------
threat_actors = [
    # Existing ones
    "APT28", "APT29", "Lazarus", "Conti", "FIN7", "REvil", "LockBit",
    "TA505", "Sandworm", "Turla", "Cobalt Group", "DarkSide", "Clop",

    # Additional APTs
    "APT1", "APT3", "APT10", "APT33", "APT34", "APT35", "APT41",
    "Mustang Panda", "Hafnium", "Gamaredon", "Kimsuky", "Andariel", "BlueNoroff", "MuddyWater",

    # Ransomware gangs
    "BlackCat", "ALPHV", "Vice Society", "Royal", "Black Basta", "Ragnar Locker", "Maze",

    # Financial / Crime groups
    "FIN4", "FIN6", "FIN8", "FIN11", "Evil Corp",

    # Others
    "UNC2452", "Lapsus$", "Killnet"
]


# -----------------------------
# HELPERS
# -----------------------------
def fetch_rss(feed_name, url):
    d = feedparser.parse(url)
    entries = []
    for entry in d.entries[:20]:
        try:
            published = parser.parse(entry.get("published", datetime.utcnow().isoformat()))
        except:
            published = datetime.utcnow()
        entries.append({
            "Source": feed_name,
            "Title": entry.title,
            "Link": entry.link,
            "Published": published
        })
    return entries

def fetch_malwarebazaar():
    resp = requests.post(malware_bazaar_api, data={"query": "get_recent", "selector": "time"})
    entries = []
    if resp.status_code == 200:
        data = resp.json()
        for sample in data.get("data", [])[:20]:
            try:
                published = parser.parse(sample.get("first_seen"))
            except:
                published = datetime.utcnow()
            entries.append({
                "Source": "MalwareBazaar",
                "Title": f"{sample.get('file_type')} — {sample.get('sha256')}",
                "Link": "https://bazaar.abuse.ch/sample/" + sample.get("sha256"),
                "Published": published
            })
    return entries

def extract_cves(text):
    """Find CVEs in a string"""
    return re.findall(r"CVE-\d{4}-\d{4,7}", text)

def get_cve_details(cve_id):
    """Fetch CVE details from NVD API"""
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            cve_item = data["result"]["CVE_Items"][0]
            desc = cve_item["cve"]["description"]["description_data"][0]["value"]
            cvss = None
            metrics = cve_item.get("impact", {})
            if "baseMetricV3" in metrics:
                cvss = metrics["baseMetricV3"]["cvssV3"]["baseScore"]
            elif "baseMetricV2" in metrics:
                cvss = metrics["baseMetricV2"]["cvssV2"]["baseScore"]
            return f"{cve_id} (CVSS: {cvss}) — {desc[:150]}..."
        else:
            return cve_id
    except:
        return cve_id

def tag_threat_actor(text):
    for actor in threat_actors:
        if actor.lower() in text.lower():
            return actor
    return None

# -----------------------------
# STREAMLIT DASHBOARD
# -----------------------------
# st.set_page_config(page_title="Threat Intel Dashboard", layout="wide")
# st.title("🛡️ Cyber Threat Intelligence Dashboard (Top 50, with CVE & Actor Tags)")

st.set_page_config(page_title="Threat Intel Dashboard", layout="wide")

# Auto-refresh every 15 minutes (900,000 ms)
st_autorefresh(interval=15 * 60 * 1000, key="refresh_dashboard")

st.title("🛡️ Cyber Threat Intelligence Dashboard 🛡️")

# --- Manual Refresh Button ---
if st.button("🔄 Refresh Now"):
    try:
        st.rerun()  # works in latest versions
    except AttributeError:
        st.experimental_rerun()  # fallback for older versions

all_entries = []
for name, url in feeds.items():
    all_entries.extend(fetch_rss(name, url))

all_entries.extend(fetch_malwarebazaar())
df = pd.DataFrame(all_entries)

# Sort by date
df = df.sort_values(by="Published", ascending=False).head(100)

# Add enrichment columns
df["CVEs"] = df["Title"].apply(extract_cves)
df["Threat Actor"] = df["Title"].apply(tag_threat_actor)

# Enrich CVE details (only if found)
df["CVE Details"] = df["CVEs"].apply(lambda x: [get_cve_details(c) for c in x] if x else [])

# Make links clickable
df["Title"] = df.apply(lambda row: f"[{row['Title']}]({row['Link']})", axis=1)

# Sidebar search
st.sidebar.header("🔍 Search & Filters")
keyword_filter = st.sidebar.text_input("Search Keyword")
actor_filter = st.sidebar.multiselect("Threat Actor", df["Threat Actor"].dropna().unique())

# --- Sidebar: Intel Agent ---
st.sidebar.markdown("## 🕵️ Intel Agent")


agent_query = st.sidebar.text_area(
    "Ask the agent (in hours, days, weeks or month)",
    "Summarize high-risk CVEs from last 5 days"
)

approve = st.sidebar.checkbox(
    "Auto-execute actions (Slack/Jira)",
    value=False,
    help="Leave unchecked to run in shadow mode"
)

if st.sidebar.button("Run Agent"):
    from agent_runner import run_agent
    res = run_agent(agent_query, df, approve=approve)

    # Display results in main area
    st.markdown("## 📝 Agent Summary")
    st.markdown(res["summary_md"])

    st.markdown("### Proposed Actions")
    for a in res["actions"]:
        st.write(f"- {a['title']} → `{a['type']}`")

    if res["executed"]:
        st.success("Actions executed:")
        st.json(res["executed"])

    with st.expander("🔍 Agent Audit Trail"):
        st.json(res["audit"])

filtered_df = df.copy()
if keyword_filter:
    filtered_df = filtered_df[filtered_df["Title"].str.contains(keyword_filter, case=False, na=False)]
if actor_filter:
    filtered_df = filtered_df[filtered_df["Threat Actor"].isin(actor_filter)]

# Display
st.write("### Latest Top 100 Threat Intel Feeds (with CVE & Actor Enrichment)")
st.write("Click on titles to open the original report/sample.")

st.write(
    filtered_df[["Published", "Source", "Title", "Threat Actor", "CVE Details"]]
    .reset_index(drop=True)
    .to_markdown(index=False)
)

# Download button
st.download_button("Download as CSV", filtered_df.to_csv(index=False), "threat_intel_enriched.csv", "text/csv")












