
import os
import sys
import subprocess
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
TEST_DIR = BASE_DIR / "detection" / "test_results"

TEST_DIR.mkdir(parents=True, exist_ok=True)

test_input = TEST_DIR / "synthetic_traffic.csv"
test_output = TEST_DIR / "synthetic_alerts.csv"

# Create synthetic packet records
records = []

def add_syn(source_port, destination_port, timestamp):
    records.append({
        "frame.time_epoch": timestamp,
        "ip.src": "192.168.1.100",
        "ipv6.src": "",
        "ip.dst": "192.168.1.200",
        "ipv6.dst": "",
        "tcp.srcport": source_port,
        "udp.srcport": "",
        "tcp.dstport": destination_port,
        "udp.dstport": "",
        "_ws.col.protocol": "TCP",
        "frame.len": 60,
        "tcp.flags": "0x0002"
    })


# Test 1: Port scan - 10 different ports
for i in range(10):
    add_syn(50000 + i, 40000 + i, 1000 + i * 0.2)

# Test 2: Repeated connection attempts - 8 SYN packets
for i in range(8):
    add_syn(51000, 45000, 1020 + i)

# Test 3: Uncommon port activity - 3 SYN packets
for i in range(3):
    add_syn(52000, 45678, 1100 + i)

# Save synthetic dataset
pd.DataFrame(records).to_csv(test_input, index=False)

# Run the actual detection engine against the synthetic data
env = os.environ.copy()
env["TRAFFIC_CSV"] = str(test_input)
env["ALERTS_OUTPUT"] = str(test_output)

result = subprocess.run(
    [sys.executable, str(BASE_DIR / "detection" / "intrusion_detection.py")],
    cwd=BASE_DIR,
    env=env,
    capture_output=True,
    text=True
)

print(result.stdout)

if result.returncode != 0:
    print(result.stderr)
    raise SystemExit("Detection test execution failed.")

# Verify generated alerts
alerts = pd.read_csv(test_output)

detected_types = set(alerts["Alert Type"])

expected_types = {
    "Possible Port Scan",
    "Repeated Connection Attempts",
    "Uncommon Destination Port"
}

missing = expected_types - detected_types

if missing:
    raise AssertionError(
        f"Some detection rules failed: {missing}"
    )

print("\n========== TEST RESULTS ==========")
print("PASS: Port scanning detection")
print("PASS: Repeated connection detection")
print("PASS: Uncommon destination port detection")
print("\nAll three detection tests passed!")
