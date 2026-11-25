
import os
import ipaddress
import pandas as pd
from pathlib import Path

# -------------------------------------------------
# PROJECT PATHS
# -------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

CSV_FILE = Path(
    os.getenv(
        "TRAFFIC_CSV",
        str(BASE_DIR / "data" / "network_traffic_detailed.csv")
    )
)

OUTPUT_DIR = BASE_DIR / "detection" / "results"

output_file = Path(
    os.getenv(
        "ALERTS_OUTPUT",
        str(OUTPUT_DIR / "intrusion_alerts.csv")
    )
)

output_file.parent.mkdir(parents=True, exist_ok=True)


# -------------------------------------------------
# LOAD AND PREPROCESS PACKET DATA
# -------------------------------------------------

if not CSV_FILE.exists():
    raise FileNotFoundError(
        f"Traffic CSV not found: {CSV_FILE}"
    )

df = pd.read_csv(CSV_FILE)

# Combine IPv4 and IPv6 source addresses
df["Source IP"] = df["ip.src"].combine_first(
    df["ipv6.src"]
)

# Combine IPv4 and IPv6 destination addresses
df["Destination IP"] = df["ip.dst"].combine_first(
    df["ipv6.dst"]
)

# Combine TCP and UDP source ports
df["Source Port"] = df["tcp.srcport"].combine_first(
    df["udp.srcport"]
)

# Combine TCP and UDP destination ports
df["Destination Port"] = df["tcp.dstport"].combine_first(
    df["udp.dstport"]
)

# Convert timestamps and ports to numeric values
df["Timestamp"] = pd.to_numeric(
    df["frame.time_epoch"],
    errors="coerce"
)

df["Source Port"] = pd.to_numeric(
    df["Source Port"],
    errors="coerce"
)

df["Destination Port"] = pd.to_numeric(
    df["Destination Port"],
    errors="coerce"
)

# Convert TCP flags from hexadecimal to integer
def parse_tcp_flags(value):
    try:
        return int(str(value), 16)
    except (ValueError, TypeError):
        return 0


df["TCP Flags"] = df["tcp.flags"].apply(
    parse_tcp_flags
)

# Remove records with missing IP addresses or timestamps
df = df.dropna(
    subset=[
        "Source IP",
        "Destination IP",
        "Timestamp"
    ]
).copy()

df = df.sort_values(
    "Timestamp"
).reset_index(drop=True)


# -------------------------------------------------
# HELPER FUNCTIONS
# -------------------------------------------------

alerts = []


def is_multicast_or_invalid(ip):
    try:
        address = ipaddress.ip_address(str(ip))

        return (
            address.is_multicast
            or address.is_unspecified
            or address.is_loopback
        )

    except ValueError:
        return True


def add_alert(
    alert_type,
    severity,
    source,
    destination,
    port,
    timestamp,
    evidence
):
    alerts.append({
        "Alert Type": alert_type,
        "Severity": severity,
        "Source IP": source,
        "Destination IP": destination,
        "Destination Port": port,
        "Timestamp": pd.to_datetime(
            timestamp,
            unit="s"
        ).strftime("%Y-%m-%d %H:%M:%S"),
        "Evidence": evidence
    })


# -------------------------------------------------
# IDENTIFY TCP SYN PACKETS
# -------------------------------------------------

# SYN flag = 1 and ACK flag = 0
syn_packets = df[
    ((df["TCP Flags"] & 0x02) != 0)
    & ((df["TCP Flags"] & 0x10) == 0)
].copy()

syn_packets = syn_packets.dropna(
    subset=["Destination Port"]
)

syn_packets["Destination Port"] = (
    syn_packets["Destination Port"].astype(int)
)

# Ignore multicast and invalid destinations
syn_packets = syn_packets[
    ~syn_packets["Destination IP"].apply(
        is_multicast_or_invalid
    )
].copy()


# -------------------------------------------------
# 1. PORT SCANNING DETECTION
# -------------------------------------------------

# Group TCP SYN packets into 10-second windows
syn_packets["Time Window"] = (
    syn_packets["Timestamp"] // 10
).astype(int)

scan_groups = syn_packets.groupby(
    [
        "Source IP",
        "Destination IP",
        "Time Window"
    ]
)

for (source, destination, window), group in scan_groups:

    unique_ports = group["Destination Port"].nunique()

    if unique_ports >= 10:

        add_alert(
            "Possible Port Scan",
            "High",
            source,
            destination,
            "Multiple",
            group["Timestamp"].min(),
            (
                f"{unique_ports} different destination ports "
                "contacted within approximately 10 seconds"
            )
        )


# -------------------------------------------------
# 2. REPEATED CONNECTION ATTEMPTS
# -------------------------------------------------

# Group TCP SYN packets into 60-second windows
syn_packets["Time Window"] = (
    syn_packets["Timestamp"] // 60
).astype(int)

connection_groups = syn_packets.groupby(
    [
        "Source IP",
        "Destination IP",
        "Destination Port",
        "Time Window"
    ]
)

for (source, destination, port, window), group in connection_groups:

    attempts = len(group)

    if attempts >= 8:

        add_alert(
            "Repeated Connection Attempts",
            "Medium",
            source,
            destination,
            int(port),
            group["Timestamp"].min(),
            (
                f"{attempts} TCP SYN packets observed "
                "within approximately 60 seconds"
            )
        )


# -------------------------------------------------
# 3. UNCOMMON DESTINATION PORT DETECTION
# -------------------------------------------------

# Common services and legitimate network activities
KNOWN_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 69,
    80, 110, 123, 137, 138, 139, 143,
    161, 162, 179, 389, 443, 445, 465,
    500, 514, 587, 631, 636, 993, 995,
    1433, 1521, 1883, 1900, 2049, 3306,
    3389, 3478, 5228, 5353, 5355, 5432,
    5900, 6379, 8009, 8080, 8443, 8883,
    8888, 27017
}

# Consider TCP SYN traffic on uncommon ports
uncommon_packets = syn_packets[
    ~syn_packets["Destination Port"].isin(
        KNOWN_PORTS
    )
].copy()

uncommon_groups = uncommon_packets.groupby(
    [
        "Source IP",
        "Destination IP",
        "Destination Port"
    ]
)

for (source, destination, port), group in uncommon_groups:

    attempts = len(group)

    if attempts >= 3:

        add_alert(
            "Uncommon Destination Port",
            "Low",
            source,
            destination,
            int(port),
            group["Timestamp"].min(),
            (
                f"{attempts} TCP SYN packets observed "
                f"on destination port {int(port)}"
            )
        )


# -------------------------------------------------
# SAVE DETECTION RESULTS
# -------------------------------------------------

alerts_df = pd.DataFrame(
    alerts,
    columns=[
        "Alert Type",
        "Severity",
        "Source IP",
        "Destination IP",
        "Destination Port",
        "Timestamp",
        "Evidence"
    ]
)

alerts_df.to_csv(
    output_file,
    index=False
)


# -------------------------------------------------
# DISPLAY INTRUSION DETECTION REPORT
# -------------------------------------------------

print("\n========== INTRUSION DETECTION REPORT ==========")

print(f"\nInput dataset: {CSV_FILE}")
print(f"Total packets analysed: {len(df)}")
print(f"TCP SYN packets analysed: {len(syn_packets)}")
print(f"Total alerts generated: {len(alerts_df)}")

if not alerts_df.empty:

    print("\nAlert distribution:")
    print(
        alerts_df["Alert Type"].value_counts()
    )

    print("\nSeverity distribution:")
    print(
        alerts_df["Severity"].value_counts()
    )

    print("\nDetected alerts:")
    print(
        alerts_df.head(20).to_string(index=False)
    )

else:

    print("\nNo suspicious patterns detected in this capture.")

print(f"\nResults saved to: {output_file}")
