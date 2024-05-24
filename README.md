# juniper_srx_log_analyzer
Analyze IDP, Screen, SecIntel and Advanced-Anti-Malware Messages

Juniper SRX Report 3.0 usage: srx_report.py [-h] [-f FILE] [-n] [-v]

optional arguments: -h, --help show this help message and exit

-f FILE, --file FILE provide path and filename to srx logs (ex. /var/log/src/mylogs, default: if not provide, /var/log/messages)

-n, --nmap perform nmap scan on detected IP addresses (default: nmap scans disabled)

-v, --verbose enable verbose output (default: verbosity disabled)

This script produces a time stamped text file and csv file.

Example Output:
Number of AAMW Alerts Blocked 0

Number of Attackers 154

List Of Attackers
193.106.29.125
5.42.66.29
14.136.23.194
159.192.106.207
51.255.62.5


