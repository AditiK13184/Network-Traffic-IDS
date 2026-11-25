import matplotlib
matplotlib.use("Agg")

import pandas as pd
import matplotlib.pyplot as plt

from pathlib import Path

# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent
CSV_FILE = BASE_DIR / "data" / "network_traffic.csv"
OUTPUT_DIR = BASE_DIR / "analysis" / "results"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Load captured network traffic
df = pd.read_csv(CSV_FILE)

# Clean column names
df.columns = df.columns.str.strip()

# Check required columns
required_columns = ["Source", "Destination", "Protocol", "Length"]

missing = [col for col in required_columns if col not in df.columns]

if missing:
    raise ValueError(f"Missing CSV columns: {missing}")

# Convert packet length to numeric
df["Length"] = pd.to_numeric(df["Length"], errors="coerce")
df = df.dropna(subset=["Length"])

# Basic traffic statistics
total_packets = len(df)
total_bytes = df["Length"].sum()
average_size = df["Length"].mean()

print("\n========== NETWORK TRAFFIC ANALYSIS ==========")

print(f"\nTotal Packets Captured: {total_packets}")
print(f"Total Data Transferred: {total_bytes} bytes")
print(f"Average Packet Size: {average_size:.2f} bytes")

# Protocol distribution
protocol_counts = df["Protocol"].value_counts()

print("\n========== PROTOCOL DISTRIBUTION ==========")
print(protocol_counts)

# Top source IP addresses
print("\n========== TOP SOURCE IPs ==========")
print(df["Source"].value_counts().head(10))

# Top destination IP addresses
print("\n========== TOP DESTINATION IPs ==========")
print(df["Destination"].value_counts().head(10))

# Save protocol statistics
protocol_counts.to_csv(
    OUTPUT_DIR / "protocol_statistics.csv",
    header=["Packet Count"]
)

# Save IP statistics
df["Source"].value_counts().head(10).to_csv(
    OUTPUT_DIR / "source_ip_statistics.csv",
    header=["Packet Count"]
)

df["Destination"].value_counts().head(10).to_csv(
    OUTPUT_DIR / "destination_ip_statistics.csv",
    header=["Packet Count"]
)

# Generate protocol distribution chart
plt.figure(figsize=(10, 6))
protocol_counts.plot(kind="bar")
plt.title("Network Protocol Distribution")
plt.xlabel("Protocol")
plt.ylabel("Number of Packets")
plt.xticks(rotation=45)
plt.tight_layout()

plt.savefig(OUTPUT_DIR / "protocol_distribution.png")
plt.close()

# Generate packet length distribution
plt.figure(figsize=(10, 6))
df["Length"].plot(kind="hist", bins=20)
plt.title("Packet Length Distribution")
plt.xlabel("Packet Length (Bytes)")
plt.ylabel("Frequency")
plt.tight_layout()

plt.savefig(OUTPUT_DIR / "packet_length_distribution.png")
plt.close()

print("\nAnalysis completed successfully!")
print(f"Results saved in: {OUTPUT_DIR}")
