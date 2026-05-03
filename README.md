# spyo
Spyo Spy Io Packet Sniffer

## Features

- Live packet capture with TUI
- Packet detail view
- Top talkers, protocols, and ports statistics
- Security alerts (SYN scan detection, large packets)
- Save captured packets to PCAP
- Multi-threaded capture
- ARP, TCP, UDP, ICMP, DNS support
- Service detection (HTTP, SSH, MySQL, etc)

## Installation
```
git clone https://github.com/Cipher1security/spyo.git
cd spyo
pip install -r requirements.txt
```

## Usage

sudo python3 spyo.py -i eth0

### Options

-i    Network interface (default: auto)
-h    Show help
