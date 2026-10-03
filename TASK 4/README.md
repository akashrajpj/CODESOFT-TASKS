# Task 4 - Network Intrusion Detection System (NIDS)

## Description

A Python-based defensive Network Intrusion Detection System that monitors network traffic and generates alerts for suspicious patterns.

### Detects

- ICMP burst / possible ping flood
- TCP port scan pattern
- Repeated SSH connection attempts

The project supports three modes:

1. Safe built-in demo
2. Offline PCAP analysis
3. Live interface monitoring

## Requirements

- Python 3.x
- Scapy

Install Scapy:

```bash
pip install -r requirements.txt
```

For Windows live capture, install Npcap and run the terminal with appropriate privileges.

## Run the safe demo

```bash
python nids.py --demo
```

The demo uses synthetic packets created in memory, so it does not attack or scan any real system.

## Analyze a PCAP file

```bash
python nids.py --pcap sample.pcap
```

## Live monitoring

Use only on a network/interface you own or are explicitly authorized to monitor.

Windows example:

```powershell
python nids.py --live "Wi-Fi"
```

Linux example:

```bash
sudo python3 nids.py --live eth0
```

## Example alerts

```text
[ALERT] Possible ICMP flood: 10.0.0.50 sent 20 ICMP packets within 10 seconds.
[ALERT] Possible TCP port scan: 10.0.0.60 contacted 10 different ports on 10.0.0.1 within 10 seconds.
[ALERT] Possible SSH brute-force activity: 10.0.0.70 made 8 SSH connection attempts within 10 seconds.
```

## Project structure

```text
Task-04-Network-Intrusion-Detection/
├── README.md
├── nids.py
└── requirements.txt
```

## Ethical use

This is a defensive and educational monitoring project. Use live packet monitoring only on systems and networks where you have permission.
