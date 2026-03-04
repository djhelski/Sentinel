# 🔍 Sentinel - Advanced Port Scanner

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![C++](https://img.shields.io/badge/C++-17-blue)
![Version](https://img.shields.io/badge/version-1.0-green)

**Sentinel** - High-performance network port scanner written in C++17.
Professional tool for security testing and network exploration.

## 📋 License

Copyright © 2026 [djhelski](https://github.com/djhelski)

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ✨ Features

- TCP Connect, SYN stealth, and UDP scanning
- Multi-threaded with rate limiting
- Service detection & banner grabbing
- CIDR support (192.168.1.0/24)
- JSON/CSV output formats
- Continuous monitoring mode

## 🚀 Quick Start

```bash
# Build
make

# Basic scan
./sentinel -t 8.8.8.8 -p 1-1000

# SYN scan (root)
sudo ./sentinel -t 192.168.1.1 -p 22,80,443 --syn --banner
