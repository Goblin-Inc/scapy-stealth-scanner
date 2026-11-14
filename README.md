# Scapy Stealth Scanner

> 🌐 **Language:** **English** | [Русский (README_Ru.md)](README_Ru.md)

A network analysis and stealth TCP port scanning utility written in **Python** using **Scapy**.

## ✨ Features
- 🕵️ **TCP Xmas Scan (`FPU` flags)** — sends crafted TCP packets (`FIN`, `PSH`, `Urgent`) to distinguish between open and filtered ports.
- 🎭 **IP Spoofing Support** — allows forging the source IP address (`src`) in packet headers.
- ⏱️ **Basic Signature Evasion** — randomized inter-packet delays and port-order shuffling.

## 🚀 Usage

```bash
pip install scapy
sudo python3 stealth_scanner.py
```
