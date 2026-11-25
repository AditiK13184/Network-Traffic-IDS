
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# =========================================================
# CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

RESULTS_DIR = BASE_DIR / "analysis" / "results"
DETECTION_DIR = BASE_DIR / "detection" / "results"
DATA_DIR = BASE_DIR / "data"

st.set_page_config(
    page_title="Network Traffic IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# =========================================================
# DARK THEME AND CUSTOM CSS
# =========================================================

st.markdown("""
<style>
    .stApp {
        background-color: #0B1120;
        color: #E5E7EB;
    }

    [data-testid="stHeader"] {
        background-color: #0B1120;
    }

    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1450px;
    }

    .main-header {
        font-size: 30px;
        font-weight: 700;
        color: #F8FAFC;
        letter-spacing: -0.7px;
        margin-bottom: 2px;
    }

    .sub-header {
        color: #94A3B8;
        font-size: 13px;
        margin-bottom: 22px;
    }

    .section-title {
        color: #F1F5F9;
        font-size: 19px;
        font-weight: 600;
        margin-top: 12px;
        margin-bottom: 15px;
    }

    .metric-card {
        background: #151F32;
        border: 1px solid #263449;
        border-radius: 12px;
        padding: 18px 20px;
        min-height: 112px;
    }

    .metric-label {
        color: #94A3B8;
        font-size: 12px;
        font-weight: 600;
        letter-spacing: 0.5px;
    }

    .metric-value {
        color: #F8FAFC;
        font-size: 27px;
        font-weight: 700;
        margin-top: 9px;
    }

    .metric-note {
        color: #94A3B8;
        font-size: 11px;
        margin-top: 3px;
    }

    .status-card {
        background: #102B27;
        border: 1px solid #176B54;
        border-radius: 12px;
        padding: 17px 20px;
    }

    .status-title {
        color: #6EE7B7;
        font-size: 15px;
        font-weight: 600;
    }

    .status-description {
        color: #A7F3D0;
        font-size: 12px;
        margin-top: 5px;
    }

    div[data-testid="stTabs"] button {
        font-size: 14px;
        font-weight: 600;
    }

    div[data-testid="stTabs"] button[aria-selected="true"] {
        color: #60A5FA;
    }

    div[data-testid="stTabs"] [data-baseweb="tab-highlight"] {
        background-color: #3B82F6;
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid #263449;
        border-radius: 10px;
    }

    hr {
        border-color: #263449;
    }

    footer {
        visibility: hidden;
    }
</style>
""", unsafe_allow_html=True)


# =========================================================
# DATA LOADING
# =========================================================

@st.cache_data
def load_csv(path):
    if path.exists():
        return pd.read_csv(path)
    return pd.DataFrame()


protocol_data = load_csv(
    RESULTS_DIR / "protocol_statistics.csv"
)

source_data = load_csv(
    RESULTS_DIR / "source_ip_statistics.csv"
)

destination_data = load_csv(
    RESULTS_DIR / "destination_ip_statistics.csv"
)

alert_data = load_csv(
    DETECTION_DIR / "intrusion_alerts.csv"
)

traffic_data = load_csv(
    DATA_DIR / "network_traffic_detailed.csv"
)


# =========================================================
# METRICS
# =========================================================

total_packets = len(traffic_data)
total_bytes = 0
average_packet_size = 0

if not traffic_data.empty and "frame.len" in traffic_data.columns:
    lengths = pd.to_numeric(
        traffic_data["frame.len"], errors="coerce"
    ).dropna()

    total_bytes = int(lengths.sum())

    if len(lengths) > 0:
        average_packet_size = lengths.mean()

total_alerts = len(alert_data)

high_alerts = 0
medium_alerts = 0
low_alerts = 0

if not alert_data.empty and "Severity" in alert_data.columns:
    severity = alert_data["Severity"].astype(str).str.lower()

    high_alerts = int((severity == "high").sum())
    medium_alerts = int((severity == "medium").sum())
    low_alerts = int((severity == "low").sum())


# =========================================================
# REUSABLE COMPONENTS
# =========================================================

def metric_card(label, value, note=""):
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
        <div class="metric-note">{note}</div>
    </div>
    """, unsafe_allow_html=True)


def style_chart(fig, height=340):
    fig.update_layout(
        height=height,
        template="plotly_dark",
        paper_bgcolor="#151F32",
        plot_bgcolor="#151F32",
        font=dict(
            family="Arial",
            color="#CBD5E1",
            size=12
        ),
        margin=dict(l=20, r=20, t=45, b=25),
        title_font=dict(size=15, color="#F1F5F9"),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        )
    )

    fig.update_xaxes(
        showgrid=False,
        zeroline=False
    )

    fig.update_yaxes(
        gridcolor="#263449",
        zeroline=False
    )

    return fig


# =========================================================
# HEADER
# =========================================================

st.markdown(
    '<div class="main-header">🛡️ Network Traffic IDS</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="sub-header">'
    'NETWORK SECURITY MONITORING & TRAFFIC ANALYSIS'
    '</div>',
    unsafe_allow_html=True
)

st.divider()


# =========================================================
# NAVIGATION TABS
# =========================================================

overview_tab, traffic_tab, intrusion_tab, explorer_tab = st.tabs([
    "⌂  Overview",
    "◈  Traffic Analysis",
    "🛡  Intrusion Detection",
    "⌕  Packet Explorer"
])


# =========================================================
# TAB 1: OVERVIEW
# =========================================================

with overview_tab:

    st.markdown(
        '<div class="section-title">Network Overview</div>',
        unsafe_allow_html=True
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        metric_card(
            "PACKETS CAPTURED",
            f"{total_packets:,}",
            "Total packets analysed"
        )

    with col2:
        metric_card(
            "DATA TRANSFERRED",
            f"{total_bytes / (1024 * 1024):.2f} MB",
            "Captured network traffic"
        )

    with col3:
        metric_card(
            "AVG. PACKET SIZE",
            f"{average_packet_size:.2f} B",
            "Average bytes per packet"
        )

    with col4:
        metric_card(
            "SECURITY ALERTS",
            str(total_alerts),
            "Detected suspicious patterns"
        )

    st.markdown("<br>", unsafe_allow_html=True)

    left, right = st.columns([1.1, 1])

    with left:
        if not protocol_data.empty:
            fig = px.pie(
                protocol_data,
                names="Protocol",
                values="Packet Count",
                hole=0.58,
                title="Protocol Distribution",
                color_discrete_sequence=px.colors.sequential.Blues_r
            )

            fig.update_traces(
                textposition="inside",
                textinfo="percent"
            )

            st.plotly_chart(
                style_chart(fig, 350),
                use_container_width=True
            )
        else:
            st.info("Protocol data unavailable.")

    with right:
        st.markdown("#### Security Status")

        if total_alerts == 0:
            st.markdown("""
            <div class="status-card">
                <div class="status-title">
                    ✓ No suspicious patterns detected
                </div>
                <div class="status-description">
                    None of the configured detection rules
                    were triggered by the captured traffic.
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.warning(
                f"{total_alerts} suspicious patterns detected."
            )

        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown("#### Alert Summary")

        a, b, c = st.columns(3)

        a.metric("High", high_alerts)
        b.metric("Medium", medium_alerts)
        c.metric("Low", low_alerts)


# =========================================================
# TAB 2: TRAFFIC ANALYSIS
# =========================================================

with traffic_tab:

    st.markdown(
        '<div class="section-title">Traffic Analysis</div>',
        unsafe_allow_html=True
    )

    left, right = st.columns(2)

    with left:
        st.markdown("#### Top Source IP Addresses")

        if not source_data.empty:
            fig = px.bar(
                source_data.head(10).sort_values("Packet Count"),
                x="Packet Count",
                y="Source",
                orientation="h",
                color="Packet Count",
                color_continuous_scale="Blues"
            )

            st.plotly_chart(
                style_chart(fig, 390),
                use_container_width=True
            )
        else:
            st.info("Source IP data unavailable.")

    with right:
        st.markdown("#### Top Destination IP Addresses")

        if not destination_data.empty:
            fig = px.bar(
                destination_data.head(10).sort_values("Packet Count"),
                x="Packet Count",
                y="Destination",
                orientation="h",
                color="Packet Count",
                color_continuous_scale="Teal"
            )

            st.plotly_chart(
                style_chart(fig, 390),
                use_container_width=True
            )
        else:
            st.info("Destination IP data unavailable.")

    st.markdown("#### Protocol Statistics")

    if not protocol_data.empty:
        st.dataframe(
            protocol_data,
            hide_index=True,
            use_container_width=True
        )


# =========================================================
# TAB 3: INTRUSION DETECTION
# =========================================================

with intrusion_tab:

    st.markdown(
        '<div class="section-title">Intrusion Detection Centre</div>',
        unsafe_allow_html=True
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Alerts", total_alerts)
    col2.metric("High Severity", high_alerts)
    col3.metric("Medium Severity", medium_alerts)
    col4.metric("Low Severity", low_alerts)

    st.markdown("<br>", unsafe_allow_html=True)

    if total_alerts == 0:
        st.success(
            "No suspicious patterns detected in the captured traffic."
        )
        st.info(
            "The detection engine analysed the available packets. "
            "No configured rule met its alert threshold."
        )

    else:
        st.warning(
            f"{total_alerts} suspicious patterns were detected."
        )

        st.markdown("#### Alert Records")

        st.dataframe(
            alert_data,
            hide_index=True,
            use_container_width=True
        )


# =========================================================
# TAB 4: PACKET EXPLORER
# =========================================================

with explorer_tab:

    st.markdown(
        '<div class="section-title">Packet Explorer</div>',
        unsafe_allow_html=True
    )

    if traffic_data.empty:
        st.warning("Detailed packet data is unavailable.")

    else:
        filtered_data = traffic_data.copy()

        search_ip = st.text_input(
            "Search IP address",
            placeholder="Enter source or destination IP..."
        )

        protocol_column = "_ws.col.protocol"

        if protocol_column in filtered_data.columns:
            protocols = sorted(
                filtered_data[protocol_column]
                .dropna()
                .astype(str)
                .unique()
            )

            selected_protocols = st.multiselect(
                "Filter by protocol",
                protocols,
                default=[]
            )

            if selected_protocols:
                filtered_data = filtered_data[
                    filtered_data[protocol_column]
                    .astype(str)
                    .isin(selected_protocols)
                ]

        if search_ip:
            ip_columns = ["ip.src", "ipv6.src", "ip.dst", "ipv6.dst"]

            available_columns = [
                col for col in ip_columns
                if col in filtered_data.columns
            ]

            if available_columns:
                mask = pd.Series(
                    False, index=filtered_data.index
                )

                for column in available_columns:
                    mask |= filtered_data[column].astype(
                        str
                    ).str.contains(
                        search_ip,
                        case=False,
                        na=False,
                        regex=False
                    )

                filtered_data = filtered_data[mask]

        st.caption(
            f"Showing {len(filtered_data):,} of "
            f"{len(traffic_data):,} packets"
        )

        st.dataframe(
            filtered_data.head(1000),
            hide_index=True,
            use_container_width=True,
            height=450
        )

        st.caption(
            "Displaying up to 1,000 matching records for performance."
        )


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.markdown(
    "<div style='text-align:center;color:#64748B;font-size:11px;'>"
    "NETWORK TRAFFIC IDS · WIRESHARK PACKET ANALYSIS · "
    "RULE-BASED INTRUSION DETECTION"
    "</div>",
    unsafe_allow_html=True
)
