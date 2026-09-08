# Network Forensics PCAP Investigation

Forensic analysis of a captured PCAP from a corporate network edge, identifying reconnaissance, C2 beaconing, and data exfiltration activity.

## Scenario
Investigated a suspicious 409-packet PCAP capture (~25s window) to identify malicious activity and produce actionable intelligence — port scanning, malware beaconing, and DNS tunneling.

## Tools
Wireshark / tshark

## Key Findings
- **Reconnaissance:** `10.4.23.102` performed horizontal + vertical SYN port scanning against 5 external hosts across 15 ports (21, 22, 23, 25, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5555, 8080, 8443) — 90 SYN packets with no ACK response, ~0.16s average interval between attempts (automated tooling, not manual).
- **C2 Beaconing:** Periodic communication between `10.4.23.102` and `206.189.23.191` over **TCP/5555**, ~1.17s average interval, highly consistent packet sizes (54/58 bytes) — classic beacon signature.
- **DNS Tunneling:** ~40 high-entropy DNS queries to `up.exfsync-cdn.net` with hex-encoded subdomains (~48 chars, entropy ~3.6–3.9 bits/char), all within a 1-second window — strong indicator of DNS-based data exfiltration.
- **Suspicious HTTP activity:** `CertUtil URL Agent` user-agent (known LOLBin abuse pattern) and a direct request for `/good.exe`.

## Methodology
Traffic profiling and endpoint identification → protocol breakdown and anomaly classification → pattern detection (port scans, beaconing, DNS tunneling) using packet timing, size distribution, and entropy analysis.

## Full Report
See [`report/report evidence.docx`](report/report%20evidence.docx) for complete methodology, all endpoint/protocol breakdowns, and full IOC list.
