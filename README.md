# 🛡️ PCAP TCP Packet Sniffer

This is a simple TCP packet sniffer that uses the **PCAP API** to capture and print TCP packet information from the network.

---
## 📁 Project Structure
```text
pcap_tcp_programming/
├── pcap_tcp_sniffer.c    # Main source file
├── myheader.h            # Header file with Ethernet/IP/TCP structure definitions
├── Makefile              # Compilation instructions
└── README.md    
```
## Output Information

The program prints the following details for each captured TCP packet:

- **Ethernet Header**: Source MAC / Destination MAC
- **IP Header**: Source IP / Destination IP
- **TCP Header**: Source Port / Destination Port
- **Payload (Message)**: Up to 20 bytes (in hex)

---

## Environment Setup

- OS: Ubuntu 20.04
- Compiler: GCC 9.4.0
- Lib: libpcap

### Install dependencies

```bash
sudo apt update
sudo apt install libpcap-dev
```

### Compile
```bash
make
```

### Run
```bash
sudo ./pcap_tcp_sniffer
#⚠️ Make sure to modify the network interface name (enp0s3, enp0s8, etc.) in the source code to match your environment.
```

### Clean
```bash
make clean
```

        