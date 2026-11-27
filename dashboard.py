
import hashlib
import json
from pathlib import Path
from datetime import datetime

import streamlit as st


BASE_DIR = Path(__file__).resolve().parent
TEST_FOLDER = BASE_DIR / "test_folder"
BASELINE_FILE = BASE_DIR / "baseline.json"
LOG_FILE = BASE_DIR / "security.log"


st.set_page_config(
    page_title="FileWatch Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)


st.markdown("""
<style>
.stApp {
    background-color: #0b1120;
    color: #e5e7eb;
}

h1, h2, h3 {
    color: #ffffff;
}

[data-testid="stMetric"] {
    background-color: #172238;
    padding: 18px;
    border-radius: 12px;
    border: 1px solid #293957;
}

[data-testid="stMetricValue"] {
    color: #60a5fa;
}

div.stButton > button {
    background-color: #2563eb;
    color: white;
    border-radius: 8px;
    border: none;
    padding: 8px 18px;
}

div.stButton > button:hover {
    background-color: #1d4ed8;
    color: white;
}
</style>
""", unsafe_allow_html=True)


def hash_file(path):
    sha256 = hashlib.sha256()

    try:
        with open(path, "rb") as file:
            while chunk := file.read(4096):
                sha256.update(chunk)

        return sha256.hexdigest()

    except OSError:
        return None


def load_baseline():
    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        return data if isinstance(data, dict) else {}

    except (OSError, json.JSONDecodeError):
        return {}


def scan_files():
    files = {}

    if not TEST_FOLDER.is_dir():
        return None

    for path in sorted(TEST_FOLDER.iterdir()):
        if path.is_file():
            file_hash = hash_file(path)

            if file_hash is not None:
                files[path.name] = file_hash

    return files


def get_severity(event):
    if event in ("MODIFIED", "DELETED"):
        return "HIGH"

    if event == "NEW":
        return "MEDIUM"

    return "SAFE"


def analyze_files(baseline, current):
    results = {}

    for name, current_hash in current.items():

        if name not in baseline:
            status = "NEW"

        elif current_hash != baseline[name]:
            status = "MODIFIED"

        else:
            status = "SAFE"

        results[name] = {
            "File": name,
            "Status": status,
            "Severity": get_severity(status),
            "Current SHA-256": current_hash
        }

    for name in baseline:
        if name not in current:
            results[name] = {
                "File": name,
                "Status": "DELETED",
                "Severity": "HIGH",
                "Current SHA-256": "N/A"
            }

    return list(results.values())


def load_events():
    events = []

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:

            for line in file:
                parts = line.strip().split(" | ")

                if len(parts) < 3:
                    continue

                old_hash = "N/A"
                new_hash = "N/A"

                for field in parts[3:]:

                    if field.startswith("OLD_SHA256="):
                        old_hash = field.replace(
                            "OLD_SHA256=", "", 1
                        )

                    elif field.startswith("NEW_SHA256="):
                        new_hash = field.replace(
                            "NEW_SHA256=", "", 1
                        )

                events.append({
                    "Time": parts[0],
                    "Event": parts[1],
                    "File": parts[2],
                    "Severity": get_severity(parts[1]),
                    "Old SHA-256": old_hash,
                    "New SHA-256": new_hash
                })

    except OSError:
        pass

    return events


# ==============================
# DASHBOARD HEADER
# ==============================

st.title("🛡️ FileWatch")
st.subheader("File Integrity Monitoring Dashboard")

st.caption(
    "Real-time visibility into file integrity, "
    "security events, and SHA-256 evidence."
)

st.divider()

if st.button("🔄 Refresh Dashboard"):
    st.rerun()


# ==============================
# LOAD DATA
# ==============================

baseline = load_baseline()
current_files = scan_files()
events = load_events()

if current_files is None:
    st.error("Test folder does not exist. Please check your project.")
    st.stop()

file_results = analyze_files(baseline, current_files)


# ==============================
# FILE METRICS
# ==============================

safe_count = sum(
    item["Status"] == "SAFE" for item in file_results
)

modified_count = sum(
    item["Status"] == "MODIFIED" for item in file_results
)

new_count = sum(
    item["Status"] == "NEW" for item in file_results
)

deleted_count = sum(
    item["Status"] == "DELETED" for item in file_results
)


if modified_count > 0 or deleted_count > 0:
    st.error("⚠️ HIGH SEVERITY: File changes detected!")

elif new_count > 0:
    st.warning("⚠️ MEDIUM SEVERITY: New files detected.")

else:
    st.success("✅ All monitored baseline files are unchanged.")


st.subheader("Security Overview")

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total Files", len(file_results))
col2.metric("Safe Files", safe_count)
col3.metric("Modified", modified_count)
col4.metric("New Files", new_count)
col5.metric("Deleted", deleted_count)


# ==============================
# SEVERITY OVERVIEW
# ==============================

st.divider()
st.subheader("🚦 Security Severity Overview")

high_count = sum(
    e["Severity"] == "HIGH" for e in events
)

medium_count = sum(
    e["Severity"] == "MEDIUM" for e in events
)

sev1, sev2, sev3 = st.columns(3)

sev1.metric("🔴 HIGH", high_count)
sev2.metric("🟠 MEDIUM", medium_count)
sev3.metric("🟢 SAFE FILES", safe_count)


# ==============================
# FILE INTEGRITY STATUS
# ==============================

st.divider()
st.subheader("📁 File Integrity Status")

if file_results:
    st.dataframe(
        file_results,
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No files found in the monitored folder.")


# ==============================
# DELETED FILES HISTORY
# ==============================

st.divider()
st.subheader("🗑️ Deleted Files History")

deleted_events = [
    event for event in events
    if event["Event"] == "DELETED"
]

if deleted_events:
    st.error(
        f"⚠️ {len(deleted_events)} file deletion event(s) recorded."
    )

    st.dataframe(
        list(reversed(deleted_events[-20:])),
        use_container_width=True,
        hide_index=True
    )

else:
    st.success("No deleted files recorded.")


# ==============================
# SECURITY EVENT HISTORY
# ==============================

st.divider()
st.subheader("🚨 Security Event History")

event_col1, event_col2, event_col3 = st.columns(3)

event_col1.metric("Total Events", len(events))

event_col2.metric(
    "Modification Events",
    sum(e["Event"] == "MODIFIED" for e in events)
)

event_col3.metric(
    "Deletion Events",
    len(deleted_events)
)

if events:
    st.dataframe(
        list(reversed(events[-20:])),
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No security events recorded yet.")


# ==============================
# EVENT SUMMARY
# ==============================

st.divider()
st.subheader("📊 Security Event Summary")

event_summary = {
    "NEW": sum(e["Event"] == "NEW" for e in events),
    "MODIFIED": sum(e["Event"] == "MODIFIED" for e in events),
    "DELETED": len(deleted_events)
}

st.bar_chart(event_summary)


# ==============================
# FOOTER
# ==============================

st.divider()

st.caption(
    "FILEWATCH | SHA-256 File Integrity Monitoring System"
)

st.caption(
    f"Last dashboard refresh: "
    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
)
