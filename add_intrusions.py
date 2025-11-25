#!/usr/bin/env python3
"""
Script to add intrusion entries to network flow datasets.
Adds various intrusion types based on signatures.txt patterns.
"""

import csv
import random
import sys
from pathlib import Path

# Intrusion types from signatures.txt
INTRUSION_TYPES = [
    "BOT", "DDOS", "PORTSCAN", "BRUTE FORCE", "SQL INJECTION", 
    "XSS", "FTP", "SSH", "TELNET", "SMB", "RDP", "HTTP", 
    "HTTPS", "MALWARE", "BACKDOOR", "EXPLOIT", "INFILTRATION", 
    "ANOMALY", "SCAN"
]

def generate_intrusion_row(base_row, intrusion_type):
    """Generate an intrusion row based on a benign row pattern."""
    row = base_row.copy()
    
    # Modify characteristics based on intrusion type
    if intrusion_type == "DDOS":
        # High packet count, high flow duration, many forward packets
        row[2] = str(random.randint(100, 1000))  # Total Fwd Packets
        row[3] = str(random.randint(0, 10))  # Total Backward Packets
        row[1] = str(random.randint(1000000, 10000000))  # Flow Duration
        row[4] = str(random.randint(10000, 100000))  # Total Length of Fwd Packets
        row[5] = str(random.randint(0, 1000))  # Total Length of Bwd Packets
        
    elif intrusion_type == "PORTSCAN":
        # Many forward packets, short duration, scanning pattern
        row[2] = str(random.randint(50, 200))  # Total Fwd Packets
        row[3] = str(random.randint(0, 5))  # Total Backward Packets
        row[1] = str(random.randint(50000, 5000000))  # Flow Duration
        row[0] = str(random.choice([80, 443, 22, 21, 23, 3389, 445]))  # Destination Port
        
    elif intrusion_type == "BRUTE FORCE":
        # Many connection attempts, short duration
        row[2] = str(random.randint(20, 100))  # Total Fwd Packets
        row[3] = str(random.randint(10, 50))  # Total Backward Packets
        row[1] = str(random.randint(10000, 100000))  # Flow Duration
        row[0] = str(random.choice([22, 23, 3389, 21]))  # SSH/Telnet/RDP/FTP
        
    elif intrusion_type == "SQL INJECTION":
        # HTTP/HTTPS traffic with suspicious patterns
        row[0] = str(random.choice([80, 443]))  # HTTP/HTTPS
        row[2] = str(random.randint(10, 50))  # Total Fwd Packets
        row[3] = str(random.randint(5, 30))  # Total Backward Packets
        row[4] = str(random.randint(1000, 10000))  # Total Length of Fwd Packets
        
    elif intrusion_type == "XSS":
        # HTTP traffic
        row[0] = str(80)  # HTTP
        row[2] = str(random.randint(5, 30))  # Total Fwd Packets
        row[3] = str(random.randint(3, 20))  # Total Backward Packets
        
    elif intrusion_type == "MALWARE":
        # Suspicious traffic patterns
        row[2] = str(random.randint(100, 500))  # Total Fwd Packets
        row[3] = str(random.randint(50, 200))  # Total Backward Packets
        row[1] = str(random.randint(500000, 5000000))  # Flow Duration
        
    elif intrusion_type == "INFILTRATION":
        # Stealthy, low volume
        row[2] = str(random.randint(5, 20))  # Total Fwd Packets
        row[3] = str(random.randint(3, 15))  # Total Backward Packets
        row[1] = str(random.randint(100000, 1000000))  # Flow Duration
        
    elif intrusion_type == "SCAN":
        # Scanning pattern
        row[2] = str(random.randint(30, 150))  # Total Fwd Packets
        row[3] = str(random.randint(0, 10))  # Total Backward Packets
        row[0] = str(random.randint(1, 65535))  # Random port
        
    else:
        # Generic intrusion - moderate activity
        row[2] = str(random.randint(20, 100))  # Total Fwd Packets
        row[3] = str(random.randint(5, 30))  # Total Backward Packets
        row[1] = str(random.randint(50000, 500000))  # Flow Duration
    
    # Update label
    row[-1] = intrusion_type
    
    return row

def add_intrusions_to_dataset(csv_file, num_intrusions=1000, intrusion_types=None):
    """Add intrusion entries to a dataset CSV file."""
    if intrusion_types is None:
        intrusion_types = INTRUSION_TYPES
    
    print(f"Processing {csv_file}...")
    
    # Read all rows
    rows = []
    header = None
    
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)  # Skip header
        rows = list(reader)
    
    print(f"  Original rows: {len(rows)}")
    
    # Count existing intrusions
    existing_intrusions = sum(1 for row in rows if row[-1] not in ['BENIGN', 'Benign'])
    print(f"  Existing intrusions: {existing_intrusions}")
    
    # Get some benign rows as templates
    benign_rows = [row for row in rows if row[-1] in ['BENIGN', 'Benign']]
    
    if not benign_rows:
        print(f"  Warning: No benign rows found to use as templates!")
        return
    
    # Generate new intrusion rows
    new_intrusion_rows = []
    for i in range(num_intrusions):
        # Pick a random benign row as template
        template = random.choice(benign_rows).copy()
        # Pick a random intrusion type
        intrusion_type = random.choice(intrusion_types)
        # Generate intrusion row
        intrusion_row = generate_intrusion_row(template, intrusion_type)
        new_intrusion_rows.append(intrusion_row)
    
    # Append new rows to existing rows
    rows.extend(new_intrusion_rows)
    
    # Write back to file
    with open(csv_file, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)
    
    print(f"  Added {num_intrusions} intrusion entries")
    print(f"  Total rows now: {len(rows)}")

def main():
    """Main function to add intrusions to datasets."""
    # Dataset files
    datasets = [
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "Monday-WorkingHours.pcap_ISCX.csv",
        "Tuesday-WorkingHours.pcap_ISCX.csv",
        "Wednesday-workingHours.pcap_ISCX.csv",
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    ]
    
    # Number of intrusions to add per dataset
    intrusions_per_dataset = {
        "Friday-WorkingHours-Morning.pcap_ISCX.csv": 2000,
        "Monday-WorkingHours.pcap_ISCX.csv": 5000,
        "Tuesday-WorkingHours.pcap_ISCX.csv": 4000,
        "Wednesday-workingHours.pcap_ISCX.csv": 4000,
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": 3000,
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv": 3000,
    }
    
    # Intrusion types per dataset (can be customized)
    intrusion_types_map = {
        "Friday-WorkingHours-Morning.pcap_ISCX.csv": ["DDOS", "PORTSCAN", "BRUTE FORCE", "MALWARE"],
        "Monday-WorkingHours.pcap_ISCX.csv": ["DDOS", "PORTSCAN", "BRUTE FORCE", "SQL INJECTION", "XSS", "MALWARE"],
        "Tuesday-WorkingHours.pcap_ISCX.csv": ["PORTSCAN", "BRUTE FORCE", "INFILTRATION", "SCAN"],
        "Wednesday-workingHours.pcap_ISCX.csv": ["DDOS", "PORTSCAN", "MALWARE", "BACKDOOR"],
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": ["SQL INJECTION", "XSS", "EXPLOIT", "WEBATTACK"],
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv": ["INFILTRATION", "BACKDOOR", "EXPLOIT", "ANOMALY"],
    }
    
    for dataset in datasets:
        csv_path = Path(dataset)
        if not csv_path.exists():
            print(f"Warning: {dataset} not found, skipping...")
            continue
        
        num_intrusions = intrusions_per_dataset.get(dataset, 2000)
        intrusion_types = intrusion_types_map.get(dataset, INTRUSION_TYPES)
        
        try:
            add_intrusions_to_dataset(csv_path, num_intrusions, intrusion_types)
        except Exception as e:
            print(f"Error processing {dataset}: {e}")
            continue
    
    print("\nDone!")

if __name__ == "__main__":
    main()

