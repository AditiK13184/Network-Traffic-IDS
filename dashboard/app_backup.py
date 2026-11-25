
from pathlib import Path

import pandas as pd
import streamlit as st

# --------------------------------------------------
# PATHS
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

RESULTS_DIR = BASE_DIR / "analysis" / "results"
DETECTION_DIR = BASE_DIR / "detection" / "results"
DATA_DIR = BASE_DIR / "data"

PROTOCOL_FILE = RESULTS_DIR / "protocol_statistics.csv"
SOURCE_FILE = RESULTS_DIR / "source_ip_statistics.csv"
DESTINATION_FILE = RESULTS_DIR / "destination_ip_statistics.csv"
PACKET_IMAGE = RESULTS_DIR / "packet_length_distribution.png"
ALERT_FILE = DETECTION_DIR / "intrusion_alerts.csv"
TRAFFIC_FILE = DATA_DIR / "network_traffic_detailed.csv"


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="Network Traffic IDS",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Network Traffic Analysis & Intrusion Detection")
st.caption("Network monitoring and rule-based security analysis dashboard")

st.divider()


# --------------------------------------------------
# DATA LOADING
# --------------------------------------------------

@st.cache_data
def load_csv(file_path):
    if file_path.exists():
        return pd.read_csv(file_path)
    return pd.DataFrame()


protocol_data = load_csv(PROTOCOL_FILE)
source_data = load_csv(SOURCE_FILE)
destination_data = load_csv(DESTINATION_FILE)
alert_data = load_csv(ALERT_FILE)
traffic_data = load_csv(TRAFFIC_FILE)


# --------------------------------------------------
# PACKET STATISTICS
# --------------------------------------------------

total_packets = len(traffic_data)

total_bytes = 0
average_packet_size = 0

if not traffic_data.empty and "frame.len" in traffic_data.columns:
    packet_lengths = pd.to_numeric(
        traffic_data["frame.len"], errors="coerce"
    ).dropna()

    total_bytes = int(packet_lengths.sum())

    if len(packet_lengths) > 0:
        average_packet_size = packet_lengths.mean()


total_alerts = len(alert_data)

high_alerts = 0
medium_alerts = 0
low_alerts = 0

if not alert_data.empty and "Severity" in alert_data.columns:
    severity = alert_data["Severity"].astype(str).str.lower()

    high_alerts = (severity == "high").sum()
    medium_alerts = (severity == "medium").sum()
    low_alerts = (severity == "low").sum()


# --------------------------------------------------
# OVERVIEW METRICS
# --------------------------------------------------

st.subheader("Network Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Packets", f"{total_packets:,}")
col2.metric("Total Data Transferred", f"{total_bytes / (1024 * 1024):.2f} MB")
col3.metric("Average Packet Size", f"{average_packet_size:.2f} bytes")
col4.metric("Intrusion Alerts", total_alerts)

st.divider()


# --------------------------------------------------
# TRAFFIC ANALYSIS
# --------------------------------------------------

st.subheader("Network Traffic Analysis")

left_col, right_col = st.columns(2)

with left_col:
    st.markdown("#### Protocol Distribution")

    if not protocol_data.empty:
        st.bar_chart(
            protocol_data.set_index("Protocol")["Packet Count"]
        )
    else:
        st.info("Protocol statistics are not available.")

with right_col:
    st.markdown("#### Top Source IP Addresses")

    if not source_data.empty:
        st.bar_chart(
            source_data.head(10).set_index("Source")["Packet Count"]
        )
    else:
        st.info("Source IP statistics are not available.")


st.markdown("#### Top Destination IP Addresses")

if not destination_data.empty:
    st.bar_chart(
        destination_data.head(10).set_index("Destination")["Packet Count"]
    )
else:
    st.info("Destination IP statistics are not available.")

st.divider()


# --------------------------------------------------
# PACKET DISTRIBUTION
# --------------------------------------------------

st.subheader("Packet Length Distribution")

if PACKET_IMAGE.exists():
    st.image(
        str(PACKET_IMAGE),
        caption="Distribution of captured packet lengths",
        use_container_width=True
    )
else:
    st.info("Packet length distribution image is not available.")

st.divider()


# --------------------------------------------------
# INTRUSION DETECTION
# --------------------------------------------------

st.subheader("Intrusion Detection Results")

if total_alerts == 0:
    st.success("No suspicious patterns detected in the captured traffic.")
else:
    st.warning(f"{total_alerts} suspicious patterns detected.")

    col1, col2, col3 = st.columns(3)

    col1.metric("High Severity", int(high_alerts))
    col2.metric("Medium Severity", int(medium_alerts))
    col3.metric("Low Severity", int(low_alerts))

    st.markdown("#### Alert Details")

    st.dataframe(alert_data, use_container_width=True)

st.divider()


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.caption(
    "Network Traffic IDS | Wireshark-based packet analysis "
    "and rule-based intrusion detection"
)
