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
51.255.62.14
128.199.181.4
69.12.5.57
157.66.48.185
220.133.20.40
159.192.104.79
216.218.206.111
114.33.37.21
220.133.92.196
218.90.122.26
111.59.56.6
185.234.216.100
31.6.41.6
80.82.78.39
197.34.152.1
59.126.37.224
59.126.252.139
159.69.50.249
71.6.135.131
218.161.74.135
122.97.138.161
74.218.29.74
61.191.26.219
112.90.146.105
18.134.228.9
125.116.93.104
170.64.228.80
77.107.131.96
154.82.84.7
194.233.88.17
45.180.244.41
84.54.51.37
117.215.210.248
202.165.17.92
147.78.103.162
221.15.131.113
45.15.157.122
1.174.20.156
184.105.247.235
51.255.62.8
51.255.62.1
42.3.173.71
59.89.238.211
114.33.11.178
120.211.97.229
59.94.100.234
150.109.50.155
216.218.206.115
46.23.108.242
47.96.67.206
1.34.85.243
59.178.23.68
80.66.66.145
118.46.200.216
185.161.248.199
200.61.42.74
47.251.67.251
114.32.100.73
115.227.49.109
139.59.40.243
194.38.23.16
31.220.1.83
104.42.38.41
220.135.113.71
92.118.39.120
165.232.79.50
118.250.6.3
122.194.11.108
216.218.206.81
114.5.16.142
51.255.62.2
45.81.23.26
184.105.247.238
139.59.17.7
36.232.38.153
183.81.169.139
91.108.240.52
146.190.248.72
170.64.234.24
217.23.10.15
95.217.124.173
74.82.47.21
120.86.253.11
94.102.49.193
88.208.52.143
147.182.149.75
209.97.180.8
135.148.232.9
184.105.139.81
104.211.2.187
159.192.105.100
51.7.185.72
167.172.42.74
51.255.62.11
51.255.62.3
185.171.202.166
58.221.47.241
213.137.244.9
95.213.139.58
162.142.125.9
180.163.30.76
159.203.60.252
113.192.81.57
128.199.137.235
104.28.155.159
2.94.200.61
195.1.144.109
157.231.51.20
206.189.79.154
45.142.182.92
194.50.16.11
104.248.29.170
123.17.251.246
175.194.181.238
107.151.243.88
107.151.200.193
107.151.243.170
184.105.247.227
167.71.85.197
216.24.212.170
124.89.86.166
184.105.247.206
42.230.183.62
51.255.62.9
143.110.168.242
59.10.46.12
65.49.1.85
87.251.64.153
113.200.137.57
27.43.204.219
162.243.173.108
77.247.70.130
220.135.61.191
45.128.232.229
52.169.251.133
185.189.182.234
141.98.7.67
36.239.50.142
164.52.0.94
31.25.92.54
115.51.1.31
173.220.1.42
122.117.175.74
117.29.44.43
139.59.143.102
167.172.158.128
122.227.97.162
143.244.133.57
91.92.254.160

Top 50 Destination Ports
Port               Count
------------------------
80                1034
443                 22
22                   4
57683                2
25                   2
15046                2
29742                2
40027                2
15746                2
50667                2
7634                 2
23251                2
2652                 2
51462                2
17533                2
51225                2
42821                2
47662                2
57701                2
28479                2
50286                2
60651                2
14873                2
42382                2
38635                2
62008                2
53699                2
54241                2
58445                2
24246                2
61167                2
60053                1
59894                1
23208                1
25269                1
65363                1
65365                1
18553                1
28913                1
30839                1
20488                1
653                  1
10691                1
8544                 1
496                  1
5076                 1
3985                 1
57697                1
4903                 1
39384                1

Top 50 Source IP Destinations
Address                  Count
------------------------------
194.233.88.17              532
47.251.67.251              145
159.192.106.207             58
61.191.26.219               30
159.192.104.79              27
111.59.56.6                 24
59.126.252.139              23
84.54.51.37                 21
91.92.254.160               21
220.133.20.40               19
220.133.92.196              18
202.165.17.92               18
193.106.29.125              15
139.59.40.243               14
91.108.240.52               13
157.66.48.185               11
220.135.113.71              11
185.161.248.199             11
128.199.181.4               11
114.33.37.21                10
1.174.20.156                 9
120.211.97.229               9
59.126.37.224                9
218.161.74.135               8
1.34.85.243                  7
114.32.100.73                7
74.218.29.74                 7
183.81.169.139               6
45.142.182.92                6
200.61.42.74                 6
77.247.70.130                6
170.64.228.80                6
115.227.49.109               6
112.90.146.105               6
114.33.11.178                5
213.137.244.9                5
80.82.78.39                  5
14.136.23.194                5
218.90.122.26                4
159.192.105.100              4
51.7.185.72                  4
185.234.216.100              4
114.5.16.142                 4
92.118.39.120                4
77.107.131.96                3
80.66.66.145                 3
5.42.66.29                   3
46.23.108.242                3
141.98.7.67                  3
45.180.244.41                3

Top 50 IDP Signatures
Signature                                      Count
----------------------------------------------------
HTTP:PHP:WP-INCLUDES-ACCESS                      530
HTTP:DIR:PARAMETER-TRAVERSE-1                     80
HTTP:DIR:PARAMETER-TRAVERSE                       67
HTTP:UA:MALICIOUS-UA-1                            51
HTTP:UNIX-FILE:ETC-PASSWD                         51
HTTP:SQL:INJ:REQ-VAR-5                            39
HTTP:PHP:CMD-INJ                                  25
HTTP:DIR:HTTP-REQ-URL                             19
HTTP:DIR:TRAVERSE-DIRECTORY                       19
HTTP:EXPLOIT:IE-SAVE-AS-HIDE                      17
HTTP:IIS:ENCODING:PERC-PERC-1                     16
HTTP:IIS:ENCODING:PERC-PERC-2                     16
HTTP:CTS:TPLINK-AX21-CMD-INJ                      13
HTTP:NETGEAR:MULT-VULN                            13
HTTP:INVALID:MSNG-HTTP-VER                        12
HTTP:CTS:JOOMLA-CMS-AUTH-BYPASS                   11
TCP:C2S:AMBIG:C2S-SYN-DATA                        10
HTTP:REQERR:REQ-MISSING-HOST                       9
HTTP:INFO-LEAK:D-LINK-MUL                          6
HTTP:INVALID:HDR-FIELD                             5
HTTP:CTS:DASAN-GPON-CMD-INJ                        5
HTTP:INFO-LEAK:DS-STORE                            4
HTTP:INVALID:MISSING-REQ                           3
HTTP:PHP:PHPMYADMIN:SETUP-SCAN                     3
HTTP:REQERR:REQ-MALFORMED-URL                      3
HTTP:DOS:APACHE-LOG4J-DOS                          2
HTTP:XSS:X-FORWARDED-FOR-INJ                       2
HTTP:MISC:DAHUA-IP-CAME-IN-DISC                    2
HTTP:REQERR:NULL-IN-HEADER                         2
HTTP:SQL:INJ:REQ-VAR-2                             2
HTTP:JOOMLA-CMS-ACE                                2
HTTP:CTS:MCAFEE-REF-XSS                            2
HTTP:SQL:INJ:JOOMLA-AVRELOADED                     2
SSL:AUDIT:RSA-EXPORT-CIPHER                        2
HTTP:INVALID:INVLD-AUTH-LEN                        2
HTTP:MISC:GENERIC-DIR-TRAVERSAL                    2
HTTP:CTS:HAPXY-EMPTY-HDRNM-BYPS                    1
HTTP:PHP:COBUB-RAZOR-ID                            1
HTTP:INFO-LEAK:MUL-VENDORS-1                       1
HTTP:REQERR:INV-HTTP-VERSION                       1
HTTP:INFO:REQ-NO-CONTENT-LENGTH                    1
HTTP:CTS:LB-LINK-ROUTER-CMD-INJ                    1
HTTP:PHP:JOOMLA-PB-PE                              1
HTTP:PHP:JOOMLA-COM-COLLECTOR                      1

Top 50 Screens Signatures
Signature                                      Count
----------------------------------------------------
SYN and FIN bits!                                255
IP spoofing!                                      70
No TCP flag!                                      17
TCP port scan!                                     8
UDP port scan!                                     3
FIN but no ACK bit!                                1

