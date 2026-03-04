📚 Sentinel - Complete Usage Guide
📑 Table of Contents
Introduction

Installation

Quick Start

Scan Types

Command Line Options

Examples

Output Formats

Performance Tuning

Advanced Features

Security Notes

Troubleshooting

FAQ

🚀 Introduction
Sentinel is a high-performance, professional-grade network port scanner written in C++17. It combines speed, reliability, and advanced features for security professionals, system administrators, and network engineers.

Key Features
✅ Multiple Scan Types: TCP Connect, SYN Stealth, UDP

✅ High Performance: Multi-threaded with rate limiting

✅ Service Detection: Banner grabbing & OS fingerprinting

✅ Flexible Output: JSON, CSV, text formats

✅ CIDR Support: Scan entire subnets

✅ Continuous Mode: Periodic scanning for monitoring

System Requirements
Component	Minimum	Recommended
OS	Linux kernel 4.0+	Ubuntu 22.04 / Debian 12
RAM	256 MB	1 GB+
CPU	1 core	4+ cores
Compiler	GCC 7+	GCC 13+
Disk	10 MB	50 MB
📦 Installation
Option 1: Build from Source (Recommended)
bash
# Clone repository
git clone https://github.com/djhelski/sentinel.git
cd sentinel

# Production build
make

# Debug build (for development)
make debug

# Static build (portable, no dependencies)
make static

# Install system-wide
sudo make install

# Test installation
sentinel -t 8.8.8.8 -p 53,80,443
Option 2: Direct Compilation
bash
# Standard build
g++ -std=c++17 -O3 -pthread sentinel.cpp -o sentinel

# With debug symbols
g++ -std=c++17 -g -O0 -pthread sentinel.cpp -o sentinel-debug

# Static build
g++ -std=c++17 -static -O3 -pthread sentinel.cpp -o sentinel-static
Option 3: Docker (Coming Soon)
bash
# Build Docker image
docker build -t sentinel .

# Run in container
docker run --rm -it --cap-add=NET_RAW --cap-add=NET_ADMIN sentinel -t 8.8.8.8 -p 1-1000
⚡ Quick Start
Basic Scan
bash
# Scan single host, default ports (1-1024)
./sentinel -t 192.168.1.1

# Scan specific ports
./sentinel -t 8.8.8.8 -p 22,80,443

# Scan port range
./sentinel -t 10.0.0.1 -p 1-1000
Advanced Scan
bash
# SYN stealth scan (requires root)
sudo ./sentinel -t 192.168.1.1 -p 1-1000 --syn --banner

# UDP scan with service detection
sudo ./sentinel -t 8.8.8.8 -p 53,161,123 --udp --dns

# CIDR network scan
./sentinel -t 192.168.1.0/24 -p 22,80,443,3389 --cidr --threads 100
Output Results
bash
# Save to JSON file
./sentinel -t 10.0.0.1 -p 1-1000 -o results.json -f json

# Verbose output with banners
./sentinel -t scanme.nmap.org -p 1-100 -v --banner

# CSV format for Excel/analysis
./sentinel -t targets.txt -p 1-1024 -o report.csv -f csv
🔍 Scan Types
1. TCP Connect Scan (Default)
Most reliable, works without root privileges.

bash
# Basic TCP scan
./sentinel -t 192.168.1.1 -p 1-1000

# With service detection
./sentinel -t 10.0.0.1 -p 1-1000 --banner --dns
Characteristics:

✅ No root required

✅ Most compatible

✅ Accurate results

❌ Slower than SYN

❌ Logged by target

2. SYN Stealth Scan
Half-open scanning, faster and less detectable.

bash
# Basic SYN scan
sudo ./sentinel -t 192.168.1.1 -p 1-1000 --syn

# With OS fingerprinting
sudo ./sentinel -t 10.0.0.1 -p 22,80,443 --syn --os-detect
Characteristics:

✅ Very fast

✅ Stealthy (no full connection)

✅ Not logged by most services

❌ Requires root

❌ May be detected by IDS

3. UDP Scan
For UDP services (DNS, DHCP, SNMP, etc.)

bash
# Common UDP ports
sudo ./sentinel -t 8.8.8.8 -p 53,67,68,123,161 --udp

# Range scan
sudo ./sentinel -t 192.168.1.1 -p 1-1000 --udp
Characteristics:

✅ Finds UDP services

✅ Essential for complete security audit

❌ Slow and unreliable

❌ Requires root

❌ Many false positives

4. CIDR Network Scan
Scan entire subnets in one command.

bash
# Class C subnet
./sentinel -t 192.168.1.0/24 -p 1-1024 --cidr

# Class B with performance tuning
./sentinel -t 10.0.0.0/16 -p 22,80,443 --cidr --threads 200 --rate 5000
5. Continuous Monitoring
Periodic scanning for change detection.

bash
# Scan every 60 seconds
./sentinel -t 192.168.1.1 -p 22,80,443 --continuous 60

# Log changes to file
./sentinel -t 10.0.0.1 -p 1-1000 --continuous 300 -o monitor.json -f json
⚙️ Command Line Options
Basic Options
Option	Description	Example	Default
-t, --target	Target IP(s) or file	-t 192.168.1.1	Required
-p, --ports	Port range	-p 1-1000,80,443	1-1024
-o, --output	Output file	-o results.txt	None
-f, --format	Output format	-f json	text
-v, --verbose	Verbose output	-v	false
Scan Type Options
Option	Description	Requires Root	Default
--syn	SYN stealth scan	✅ Yes	false
--udp	UDP scan	✅ Yes	false
(none)	TCP connect scan	❌ No	default
Performance Options
Option	Description	Example	Default
--threads	Number of threads	--threads 50	CPU×2
--timeout	Timeout in ms	--timeout 500	200
--rate	Packets per second	--rate 1000	0 (unlimited)
--randomize	Randomize port order	--randomize	false
Discovery Options
Option	Description	Example	Default
--banner	Grab service banners	--banner	false
--dns	Reverse DNS lookup	--dns	false
--os-detect	OS fingerprinting	--os-detect	false
--no-ping	Skip ICMP ping	--no-ping	false
--service	Service detection	--service	true
Advanced Options
Option	Description	Example	Default
--cidr	Enable CIDR notation	--cidr	false
--exclude	Exclude ports	--exclude 22,23	None
--continuous	Continuous mode (sec)	--continuous 60	false
--vuln	Vulnerability check	--vuln	false
Miscellaneous
Option	Description
-h, --help	Show help menu
--version	Show version information
📝 Examples
1. Basic Network Scan
bash
# Scan home network
./sentinel -t 192.168.1.1 -p 1-1024

# Scan multiple hosts
./sentinel -t 192.168.1.1,192.168.1.2,10.0.0.1 -p 22,80,443
2. Professional Security Audit
bash
# Complete audit with all features
sudo ./sentinel -t 10.0.0.0/24 \
  -p 1-65535 \
  --syn \
  --banner \
  --dns \
  --os-detect \
  --threads 200 \
  --rate 5000 \
  -o full_audit.json \
  -f json \
  -v
3. Web Server Scan
bash
# Scan common web ports with banner grabbing
./sentinel -t 192.168.1.100 \
  -p 80,443,8080,8443 \
  --banner \
  --dns \
  --service
4. Database Server Scan
bash
# Find database services
./sentinel -t 10.0.0.50 \
  -p 3306,5432,27017,6379,9200 \
  --banner \
  --vuln
5. Quick Vulnerability Check
bash
# Check for common vulnerable ports
./sentinel -t 192.168.1.1 \
  -p 21,22,23,445,3389,5900 \
  --banner \
  --vuln \
  -v
6. Firewall Testing
bash
# Test firewall rules
sudo ./sentinel -t 192.168.1.1 \
  -p 1-1000 \
  --syn \
  --randomize \
  --rate 100
7. Continuous Monitoring Script
bash
#!/bin/bash
# monitor.sh - Continuous network monitoring

TARGETS="192.168.1.1 192.168.1.2 10.0.0.1"
PORTS="22,80,443,3389"
LOG_DIR="/var/log/sentinel"

mkdir -p $LOG_DIR

while true; do
    DATE=$(date +%Y%m%d_%H%M%S)
    ./sentinel -t "$TARGETS" -p "$PORTS" \
        -o "$LOG_DIR/scan_$DATE.json" \
        -f json \
        --banner
    
    echo "Scan completed at $DATE"
    sleep 300  # 5 minutes
done
8. From Target File
bash
# targets.txt
192.168.1.1
192.168.1.2
10.0.0.1
8.8.8.8
# Add more IPs...

./sentinel -t targets.txt -p 1-1000 -o results.json -f json
9. Performance Benchmark
bash
# Test maximum performance
time ./sentinel -t 8.8.8.8 -p 1-10000 --threads 500 --rate 10000
10. Stealth Mode
bash
# Maximum stealth, minimal detection
sudo ./sentinel -t 192.168.1.1 \
  -p 1-1000 \
  --syn \
  --randomize \
  --rate 10 \
  --timeout 1000
📊 Output Formats
Text Output (Default)
bash
./sentinel -t 8.8.8.8 -p 53,80,443 -o results.txt
text
Sentinel Scan Results - 2024-03-15 10:30:45
============================================

Target: 8.8.8.8
PORT      STATE    SERVICE    TIME(ms)
---------------------------------------
53/udp    open     dns        45
80/tcp    open     http       12
443/tcp   open     https      15

Statistics:
  Total ports: 3
  Open ports: 3
  Scan time: 2.3 seconds
JSON Output
bash
./sentinel -t 8.8.8.8 -p 53,80,443 -o results.json -f json
json
{
  "scan_info": {
    "timestamp": "2024-03-15 10:30:45",
    "version": "2.0.0",
    "targets": ["8.8.8.8"]
  },
  "statistics": {
    "total_ports": 3,
    "open_ports": 3,
    "scan_duration": 2.3
  },
  "results": [
    {
      "target": "8.8.8.8",
      "port": 53,
      "protocol": "udp",
      "state": "open",
      "service": "dns",
      "response_time_ms": 45
    }
  ]
}
CSV Output
bash
./sentinel -t 8.8.8.8 -p 53,80,443 -o results.csv -f csv
csv
timestamp,target,port,protocol,state,service,response_time_ms,banner
2024-03-15 10:30:45,8.8.8.8,53,udp,open,dns,45,
2024-03-15 10:30:45,8.8.8.8,80,tcp,open,http,12,
2024-03-15 10:30:45,8.8.8.8,443,tcp,open,https,15,
⚡ Performance Tuning
Thread Configuration
bash
# CPU cores × 2 (default)
./sentinel -t 8.8.8.8 -p 1-1000 --threads $(nproc)

# Maximum threads for fast scan
./sentinel -t 192.168.1.0/24 -p 1-1000 --threads 500

# Conservative for stability
./sentinel -t 10.0.0.1 -p 1-65535 --threads 50
Rate Limiting
bash
# Slow scan (10 packets/sec) - stealthy
sudo ./sentinel -t 192.168.1.1 -p 1-1000 --syn --rate 10

# Medium scan (1000 packets/sec)
./sentinel -t 8.8.8.8 -p 1-10000 --rate 1000

# Maximum speed (unlimited)
./sentinel -t 10.0.0.1 -p 1-1000 --rate 0
Timeout Adjustment
bash
# Fast local network
./sentinel -t 192.168.1.1 -p 1-1000 --timeout 100

# Slow remote network
./sentinel -t 8.8.8.8 -p 1-1000 --timeout 1000

# Unstable connection
./sentinel -t 10.0.0.1 -p 1-1000 --timeout 3000
Performance Recommendations
Network Type	Threads	Rate	Timeout
Local LAN	100-200	5000+	100ms
Data Center	50-100	1000-5000	200ms
Internet	20-50	100-500	500ms
Stealth	5-10	10-50	1000ms
Satellite	10-20	50-100	3000ms
🛡️ Advanced Features
OS Fingerprinting
bash
# Detect operating system based on TTL
./sentinel -t 192.168.1.1 -p 22,80 --os-detect
text
Port 22/tcp open - TTL: 64 (Linux/Unix)
Port 80/tcp open - TTL: 128 (Windows)
Vulnerability Checking
bash
# Check for known vulnerable versions
./sentinel -t 10.0.0.1 -p 21,22,80,443 --vuln --banner
text
Port 21/tcp open - FTP vsftpd 2.3.4 [VULNERABLE: CVE-2011-2523]
Port 80/tcp open - Apache 2.4.49 [VULNERABLE: CVE-2021-41773]
Service Detection Database
Built-in service signatures:

bash
# Common services automatically detected
21/tcp  → FTP
22/tcp  → SSH
23/tcp  → Telnet
25/tcp  → SMTP
53/udp  → DNS
80/tcp  → HTTP
443/tcp → HTTPS
3306/tcp → MySQL
5432/tcp → PostgreSQL
27017/tcp → MongoDB
# ... and 100+ more
Custom Port Exclusions
bash
# Skip sensitive ports
./sentinel -t 192.168.1.1 -p 1-65535 --exclude 22,23,445

# Skip ranges
./sentinel -t 10.0.0.1 -p 1-1000 --exclude 800-900
⚠️ Security Notes
Legal Disclaimer
text
IMPORTANT: Sentinel is designed for authorized security testing only.
Users are solely responsible for compliance with all applicable laws
and regulations. Unauthorized scanning of networks may be illegal
and unethical.
Best Practices
Always get written permission before scanning any network

Use rate limiting to avoid network disruption

Respect robots.txt and network policies

Document all tests for compliance

Notify administrators before large scans

Detection Avoidance
bash
# Stealth configuration
sudo ./sentinel -t target.com \
  --syn \
  --randomize \
  --rate 10 \
  --timeout 2000 \
  --no-ping
🔧 Troubleshooting
Common Issues
1. "Permission denied" for SYN/UDP scan
bash
# Solution: Use sudo
sudo ./sentinel -t 192.168.1.1 -p 1-1000 --syn
2. "Cannot open output file"
bash
# Check permissions
touch test.txt
ls -la test.txt
./sentinel -t 8.8.8.8 -p 80 -o test.txt
3. Scan too slow
bash
# Increase threads and rate
./sentinel -t 10.0.0.1 -p 1-1000 --threads 200 --rate 5000
4. "No hosts up" but they are
bash
# Skip ping check
./sentinel -t 192.168.1.1 -p 1-1000 --no-ping
5. Memory issues
bash
# Reduce batch size (compile-time option)
# Add -DBATCH_SIZE=50 to CXXFLAGS
Error Messages
Error	Cause	Solution
Socket error: Permission denied	Need root	Use sudo
Invalid IP address	Wrong format	Check IP syntax
Cannot resolve hostname	DNS issue	Use IP directly
Timeout	Network slow	Increase --timeout
No targets specified	Missing -t	Add target parameter
Debug Mode
bash
# Run with verbose output
./sentinel -t 8.8.8.8 -p 53,80 -v

# Debug build with extra logging
make debug
./bin/sentinel-debug -t 127.0.0.1 -p 1-100 -v
❓ FAQ
General Questions
Q: Is Sentinel better than Nmap?
A: Sentinel is complementary to Nmap. It's faster for large scans and has a simpler interface, but Nmap has more features.

Q: Can I use Sentinel on Windows?
A: Currently Linux/Unix only. Windows support planned for v3.0.

Q: Is it really free?
A: Yes! MIT License - completely free for any use.

Technical Questions
Q: How many ports can I scan?
A: Up to 65535 ports. Performance depends on threads and rate limit.

Q: What's the maximum speed?
A: On good hardware: 10,000+ packets/second with proper tuning.

Q: Does it support IPv6?
A: Basic IPv6 support coming in v2.5. Current version is IPv4 only.

Security Questions
Q: Can this be detected?
A: SYN scan is stealthy but can be detected by IDS/IPS systems.

Q: Is it legal to scan my own network?
A: Yes, scanning your own network is perfectly legal.

Q: Can I scan cloud services?
A: Check the cloud provider's ToS first. Most allow security testing with permission.

📈 Performance Benchmarks
Configuration	Ports	Threads	Rate	Time
Localhost	1000	50	unlimited	2s
LAN (1Gbps)	1000	100	5000	5s
LAN (1Gbps)	65535	200	10000	45s
Internet	1000	50	500	30s
Internet	1000	20	100	60s
Actual performance varies by network conditions

🤝 Contributing
We welcome contributions! See CONTRIBUTING.md for guidelines.

# Development Setup

git clone https://github.com/djhelski/sentinel.git
cd sentinel
make debug
./bin/sentinel-debug -t 127.0.0.1 -p 1-100 -v
Report Issues
GitHub Issues: https://github.com/djhelski/sentinel/issues

Email: djhelinski10@gmail.com

📄 License
MIT License - see LICENSE file for details.

Copyright © 2026 djhelski

Made with ⚡ by security professionals, for security professionals

Last updated: March 2026 | Version 1.0.0
