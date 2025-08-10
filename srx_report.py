import subprocess
import string
import os
import os.path
import time
import shlex
import filecmp
import fnmatch
from datetime import date, datetime, timedelta
import collections
import sys
import argparse
import codecs

#RELEASE NOTES
#   DATE        VER         AUTHOR          DESCRIPTION
#   07-2021     1.0         MOOJIT          INITIAL RELEASE
#   01-2023     2.0         MOOJIT          ADDED SECINTEL, AAMW PROCESSING
#   10-2023     3.0         MOOJIT          FIXED DNSF
#   11-2023     4.0         MOOJIT          FIXED SCREEN_IP REPORTING
#   12-2023     5.0         MOOJIT          FIXED SCREEN_IP FILE REPORTING BEHAVIOR
#   12-2023     6.0         MOOJIT          FIXED SCREEN_IP TOP 50 REPORTING BEHAVIOR
#   05-2024     7.0         MOOJIT          CHANGED SCREEN TO RT_SCREEN FILTER
#   08-2024     8.0         MOOJIT          ADDED RT_FLOW_SESSION_DENY REPORTING
#   10-2024     9.0         MOOJIT          FIXED CODEC BUG ON PYTHON3. FIXED SIGNATURE DETERMINATION FOR REVERSE_SHELL EVENTS.
#   10-2024     10.0        MOOJIT          ADD STANDARD INIT/MAIN SECTIONS.
#   08-2025	11.0        MOOJIT          ADDED FIX FOR RT_FLOW SIGNATURE

def main():
    MAJOR_VERSION = 11
    MINOR_VERSION = 0

    JUNIPER_VERSION = "Junos: 23.4R2-S5.5"

    NumberOfP1s = 0
    NumberOfP2s = 0
    NumberOfP3s = 0
    NumberOfP4s = 0
    NumberOfP5s = 0
    NumberOfP6s = 0
    NumberOfP7s = 0
    NumberOfP8s = 0
    NumberOfP9s = 0
    IDP_Allow = 0
    IDP_Drop = 0
    SECINTEL_Permit = 0
    SECINTEL_Block = 0
    AAMW_Permit = 0
    AAMW_Block = 0
    DENY_Counter = 0

    Match = False

    EnableP1Report = True
    EnableP2Report = True
    EnableP3Report = True
    EnableP4Report = True
    EnableP5Report = True
    EnableP6Report = True
    EnableP7Report = True
    EnableP8Report = True
    EnableP9Report = True
    EnableNmapScan = False
    EnableCSVCreation = True
    EnableVerbosity = False
    CustomPath = False

    P1 = "IDP ATTACK, SECINTEL, AAMW AND SCREENS"
    P2 = "IDP ATTACK"
    P3 = "SCREENS"
    P4 = "SCREENS TCP"
    P5 = "SCREENS UDP"
    P6 = "SECINTEL"
    P7 = "AAMW"
    P8 = "SCREENS IP"
    P9 = "SESSION DENIALS"

    P1list = []
    P2list = []
    P3list = []
    P4list = []
    P5list = []
    P6list = []
    P7list = []
    P8list = []
    P9list = []

    P1_IP_list = []
    P2_IP_list = []
    P3_IP_list = []
    P4_IP_list = []
    P5_IP_list = []
    P6_IP_list = []

    P1_IP_Unique = []
    P2_IP_Unique = []
    P3_IP_Unique = []
    P4_IP_Unique = []
    P5_IP_Unique = []
    P6_IP_Unique = []

    NumberOfP1IPs = 0
    NumberOfP2IPs = 0
    NumberOfP3IPs = 0
    NumberOfP4IPs = 0
    NumberOfP5IPs = 0
    NumberOfP6IPs = 0

    P6_Port_list = []
    P6_Port_list_Counter = []
    P6_Src_IP_list = []
    P6_Src_IP_list_Counter = []

    P1_Port_list = []
    P1_Port_list_Counter = []
    P1_Src_IP_list = []
    P1_Src_IP_list_Counter = []
    P1_IDP_Signature_list = []
    P1_Screen_Signature_list = []
    P1_IDP_Signature_list_Counter = []
    P1_Screen_Signature_list_Counter = []

    path = "/var/log/"
    filename = "messages*"

    NumberOfAttackers = 0

    print("\nJuniper SRX Report " + str(MAJOR_VERSION) + "." + str(MINOR_VERSION) + " supporting Juniper versions up to " + JUNIPER_VERSION)

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=False, help="provide path and filename to srx logs (ex: /var/log/src/mylogs, default: /var/log/messages)")
    parser.add_argument("-n", "--nmap", required=False, help="perform nmap scan on detected IP addresses (default: nmaps scans disable)", action="store_true")
    parser.add_argument("-v", "--verbose", required=False, help="enable verbose output (default: verbosity disabled)", action="store_true")
    args = parser.parse_args()

    if args.file:
        CustomPath = True
        print("{:s} custom path will be used!".format(args.file))
    if args.nmap:
        EnableNmapScan = True
        print("nmap scans enabled!")
    if args.verbose:
        EnableVerbosity = True
        print("verbosity enabled!")
         
    #GET START TIME
    start_time = datetime.now()
    print("\nSTART TIME: {}".format(start_time.strftime("%m/%d/%Y %H:%M:%S.%f")))

    if CustomPath == True:
        path = ""
        var = args.file.split("/")
        seps = len(var)
        filename = var[seps-1]
        for item in range(1,seps-1):
            var_1 = "/" + var[item]
            path = path + var_1
        path = path + "/"
        filename = filename + "*"

    if EnableVerbosity == True:
        print(path)
        print(filename)

    files = os.listdir(path)
    files.sort( key=lambda x: os.stat(os.path.join(path, x)).st_mtime)

    for file in files:
        if fnmatch.fnmatch(file, 'messages*'):
            print(file)
            f = codecs.open(path + file, "r", encoding="utf-8", errors="ignore")
            
            for line in f:

                if EnableP1Report == True:
                    if line.find("IDP_ATTACK") > -1 or line.find("RT_SCREEN") > -1 or line.find("RT_SECINTEL") > -1 or line.find("AAMW_ACTION") > -1 or line.find("RT_FLOW_SESSION_DENY") > -1:
                        Match = False
                        for item in P1list:
                            if item == line:
                                Match = True
                                break
                        
                        if Match == False:
                            NumberOfP1s = NumberOfP1s + 1
                            P1list.append(line)
                
                if EnableP2Report == True:
                    if line.find("IDP_ATTACK") > -1:
                        Match = False
                        for item in P2list:
                            if item == line:
                                Match = True
                                break
                        
                        if Match == False:
                            NumberOfP2s = NumberOfP2s + 1
                            P2list.append(line)
                            
                            if line.find("NONE") > -1:
                                IDP_Allow = IDP_Allow + 1
                            elif line.find("DROP") > -1:
                                IDP_Drop = IDP_Drop + 1
                
                if EnableP3Report == True:
                    if line.find("RT_SCREEN") > -1:
                        Match = False
                        for item in P3list:
                            if item == line:
                                Match = True
                                break
                        
                        if Match == False:
                            NumberOfP3s = NumberOfP3s + 1
                            P3list.append(line)
                            
                if EnableP4Report == True:
                    if line.find("SCREEN_TCP") > -1:
                        Match = False
                        for item in P4list:
                            if item == line:
                                Match = True
                                break
                        
                        if Match == False:
                            NumberOfP4s = NumberOfP4s + 1
                            P4list.append(line)
                            
                if EnableP5Report == True:
                    if line.find("SCREEN_UDP") > -1:
                        Match = False
                        for item in P5list:
                            if item == line:
                                Match = True
                                break
                        
                        if Match == False:
                            NumberOfP5s = NumberOfP5s + 1
                            P5list.append(line)
                 
                if EnableP8Report == True:
                    if line.find("SCREEN_IP") > -1:
                        Match = False
                        for item in P8list:
                            if item == line:
                                Match = True
                                break

                        if Match == False:
                            NumberOfP8s = NumberOfP8s + 1
                            P8list.append(line)
                            
                if EnableP6Report == True:
                    if line.find("RT_SECINTEL") > -1:
                        Match = False
                        for item in P6list:
                            if item == line:
                                Match = True
                                break
                        
                        if Match == False:
                            NumberOfP6s = NumberOfP6s + 1
                            P6list.append(line)
                            
                            if line.find("PERMIT") > -1:
                                SECINTEL_Permit = SECINTEL_Permit + 1
                            elif ( (line.find("BLOCK") > -1) or (line.find("drop") > -1) ):
                                SECINTEL_Block = SECINTEL_Block + 1
                           
                if EnableP7Report == True:
                    if line.find("AAMW_ACTION") > -1:
                        Match = False
                        for item in P7list:
                            if item == line:
                                Match = True
                                break
                        
                        if Match == False:
                            NumberOfP7s = NumberOfP7s + 1
                            P7list.append(line)
                            
                            if line.find("PERMIT") > -1:
                                AAMW_Permit = AAMW_Permit + 1
                            elif line.find("BLOCK") > -1:
                                AAMW_Block = AAMW_Block + 1
                                
                if EnableP9Report == True:
                    if line.find("RT_FLOW_SESSION_DENY") > -1:
                        Match = False
                        for item in P9list:
                            if item == line:
                                Match = True
                                break
                        
                        if Match == False:
                            NumberOfP9s = NumberOfP9s + 1
                            P9list.append(line)
            
            f.close

    P1list.reverse()
    P2list.reverse()
    P3list.reverse()
    P4list.reverse()
    P5list.reverse()
    P6list.reverse()
    P7list.reverse()
    P9list.reverse()

    #FIRST LEVEL P1LIST FILTER  
    for line in P1list:
        if line.find("IDP_ATTACK") > -1:
            timestamp = line.split(" ")
            juniper_type = line.split(":")
            ip_src = line.split("<")
            ip_src = ip_src[1].split("/")
            src_port = line.split("<")
            src_port = src_port[1].split("/")
            src_port = src_port[1].split("-")
            ip_dest = line.split(">")
            ip_dest = ip_dest[1].split("/")
            dest_port = line.split(">")
            dest_port = dest_port[1].split("/")
            dest_port = dest_port[1].split(">")
            signature = line.split("=")
            signature = signature[5].split(",")
            severity = line.split("=")
            severity = severity[4].split(",")
            action = line.split("=")
            action = action[3].split(",")
            if len(timestamp[1]) > 1:
                var = timestamp[0] + " " + timestamp[1] + " " + timestamp[2] + "," + timestamp[3] + "," + juniper_type[3].strip() + "," + ip_src[0].strip() + "," + src_port[0].strip() + "," + ip_dest[0].strip() + "," + dest_port[0].strip() + "," + signature[0].strip() + "," + severity[0].strip() + "," + action[0].strip()
            else:
                var = timestamp[0] + " " + timestamp[1] + timestamp[2] + " " + timestamp[3] + "," + timestamp[4] + "," + juniper_type[3].strip() + "," + ip_src[0].strip() + "," + src_port[0].strip() + "," + ip_dest[0].strip() + "," + dest_port[0].strip() + "," + signature[0].strip() + "," + severity[0].strip() + "," + action[0].strip()       
            NumberOfP1IPs = NumberOfP1IPs + 1
            P1_IP_list.append(var)

        elif line.find("RT_SCREEN") > -1:
            timestamp = line.split(" ")
            juniper_type = line.split(":")
            ip_src = line.split(":")
            ip_src = ip_src[5].strip()
            src_port = line.split(":")
            src_port = src_port[6].split(",")
            src_port = src_port[0].strip()
            ip_dest = line.split(":")
            ip_dest = ip_dest[7].strip()
            dest_port = line.split(":")
            dest_port = dest_port[8].split(",")
            dest_port = dest_port[0].strip()
            signature = line.split(":")
            signature = signature[4].split(":")
            signature = signature[0].replace("source",":")
            signature = signature.split(":")
            offset = line.find("action:")
            if offset > -1:
                action = line[offset:].split(":")
                action = action[1].strip()
            else:
                action = "none"
            if line.find("SCREEN_IP") > -1:
                ip_src = line.split(":")
                ip_src = ip_src[5].split(",")
                ip_src = ip_src[0].strip()
                
                ip_dest = line.split(":")
                ip_dest = ip_dest[6].split(",")

                ip_dest = ip_dest[0].strip()
                if len(timestamp[1]) > 1:
                    var = timestamp[0] + " " + timestamp[1] + " " + timestamp[2] + "," + timestamp[3] + "," + juniper_type[3].strip() + "," + ip_src + "," + "," + ip_dest + "," + "," + signature[0].strip() + "," + "," + action
                else:
                    ip_src = ip_src.split(",")
                    ip_src = ip_src[0].strip()
                    var = timestamp[0] + " " + timestamp[1] + timestamp[2] + " " + timestamp[3] + "," + timestamp[4] + "," + juniper_type[3].strip() + "," + ip_src + "," + "," + ip_dest + "," + "," + signature[0].strip() + "," + "," + action
            else:
                if len(timestamp[1]) > 1:
                    var = timestamp[0] + " " + timestamp[1] + " " + timestamp[2] + "," + timestamp[3] + "," + juniper_type[3].strip() + "," + ip_src + "," + src_port + "," + ip_dest + "," + dest_port + "," + signature[0].strip() + "," + "," + action
                else:
                    var = timestamp[0] + " " + timestamp[1] + timestamp[2] + " " + timestamp[3] + "," + timestamp[4] + "," + juniper_type[3].strip() + "," + ip_src + "," + src_port + "," + ip_dest + "," + dest_port + "," + signature[0].strip() + "," + "," + action
            NumberOfP1IPs = NumberOfP1IPs + 1
            P1_IP_list.append(var)
            
        elif line.find("RT_FLOW_SESSION_DENY") > -1:
            timestamp = line.split(" ")
            juniper_type = line.split(":")
            ip_src = line.split(":")
            ip_src = ip_src[4].split(" ")
            ip_src = ip_src[3].split("/")
            
            if ip_src is not None:
                 src_port = ip_src[1].split("-")
                 src_port = src_port[0].strip()
            
                 ip_src = ip_src[0].strip()

                 ip_dest = line.split(">")
                 ip_dest = ip_dest[1].split(" ")
                 ip_dest = ip_dest[0].split("/")
                 dest_port = ip_dest[1].strip()
                 ip_dest = ip_dest[0].strip()
            else:
                 ip_src = "N/A"
                 ip_dest = "N/A"
                 src_port = "N/A"
                 dest_port = "N/A"
            
            signature = "N/A"
            severity = "N/A"
            action = "N/A"
            
            if len(timestamp[1]) > 1:
                var = timestamp[0] + " " + timestamp[1] + " " + timestamp[2] + "," + timestamp[3] + "," + juniper_type[3].strip() + "," + ip_src.strip() + "," + src_port.strip() + "," + ip_dest.strip() + "," + dest_port.strip() + "," + signature.strip() + "," + severity.strip() + "," + action.strip()
            else:
                var = timestamp[0] + " " + timestamp[1] + timestamp[2] + " " + timestamp[3] + "," + timestamp[4] + "," + juniper_type[3].strip() + "," + ip_src.strip() + "," + src_port.strip() + "," + ip_dest.strip() + "," + dest_port.strip() + "," + signature.strip() + "," + severity.strip() + "," + action.strip()       
            NumberOfP1IPs = NumberOfP1IPs + 1
            P1_IP_list.append(var)
            
        elif line.find("RT_SECINTEL") > -1:
            timestamp = line.split(" ")
            juniper_type = line.split(":")
            signature = "N/A"
            print(line)
            if line.find("source-address") > -1:
                myindex = line.find("source-address")
                ip_src = line[myindex:].split("=")
                ip_src = ip_src[1].split(" ")
                ip_src = ip_src[0].strip()
            if line.find("source-port") > -1:
                myindex = line.find("source-port")
                src_port = line[myindex:].split("=")
                src_port = src_port[1].split(" ")
                src_port = src_port[0].strip()
            if line.find("destination-address") > -1:
                myindex = line.find("destination-address")
                ip_dest = line[myindex:].split("=")
                ip_dest = ip_dest[1].split(" ")
                ip_dest = ip_dest[0].strip()
            if line.find("destination-port") > -1:
                myindex = line.find("destination-port")
                dest_port = line[myindex:].split("=")
                dest_port = dest_port[1].split(" ")
                dest_port = dest_port[0].strip()
            if line.find("sub-category") > -1:
                myindex = line.find("sub-category")
                if line.find("DNSF_ACTION_LOG") > -1:
                    signature = line[myindex:].split("=")
                    signature = signature[2].split(" ")
                    signature = signature[0].strip()
                else:
                    signature = line[myindex:].split("=")
                    signature = signature[1].split(" ")
                    signature = signature[0].strip()
            if line.find("threat-severity") > -1:
                myindex = line.find("threat-severity")
                severity = line[myindex:].split("=")
                severity = severity[1].split(" ")
                severity = severity[0].strip()
            if line.find("action") > -1:
                myindex = line.find("action")
                action = line[myindex:].split("=")
                action = action[1].split(" ")
                action = action[0].strip()
            if len(timestamp[1]) > 1:
                var = timestamp[0] + " " + timestamp[1] + " " + timestamp[2] + "," + timestamp[3] + "," + juniper_type[3].strip() + "," + ip_src.strip() + "," + src_port.strip() + "," + ip_dest.strip() + "," + dest_port.strip() + "," + signature.strip() + "," + severity.strip() + "," + action.strip()
            else:
                var = timestamp[0] + " " + timestamp[1] + timestamp[2] + " " + timestamp[3] + "," + timestamp[4] + "," + juniper_type[3].strip() + "," + ip_src.strip() + "," + src_port.strip() + "," + ip_dest.strip() + "," + dest_port.strip() + "," + signature.strip() + "," + severity.strip() + "," + action.strip()       
            NumberOfP1IPs = NumberOfP1IPs + 1
            P1_IP_list.append(var)
            
        elif line.find("AAMW_ACTION") > -1:
            timestamp = line.split(" ")
            juniper_type = line.split(":")
            if line.find("source-address") > -1:
                myindex = line.find("source-address")
                ip_src = line[myindex:].split("=")
                ip_src = ip_src[1].split(" ")
                ip_src = ip_src[0].strip()
            if line.find("source-port") > -1:
                myindex = line.find("source-port")
                src_port = line[myindex:].split("=")
                src_port = src_port[1].split(" ")
                src_port = src_port[0].strip()
            if line.find("destination-address") > -1:
                myindex = line.find("destination-address")
                ip_dest = line[myindex:].split("=")
                ip_dest = ip_dest[1].split(" ")
                ip_dest = ip_dest[0].strip()
            if line.find("destination-port") > -1:
                myindex = line.find("destination-port")
                dest_port = line[myindex:].split("=")
                dest_port = dest_port[1].split(" ")
                dest_port = dest_port[0].strip()
            if line.find("url") > -1:
                myindex = line.find("url")
                signature = line[myindex:].split("=")
                signature = signature[1].split(" ")
                signature = (signature[0].replace(",","_")).strip()
            if line.find("verdict-number") > -1:
                myindex = line.find("verdict-number")
                severity = line[myindex:].split("=")
                severity = severity[1].split(" ")
                severity = severity[0].strip()
            if line.find("action") > -1:
                myindex = line.find("action")
                action = line[myindex:].split("=")
                action = action[1].split(" ")
                action = action[0].strip()
            if len(timestamp[1]) > 1:
                var = timestamp[0] + " " + timestamp[1] + " " + timestamp[2] + "," + timestamp[3] + "," + juniper_type[3].strip() + "," + ip_src.strip() + "," + src_port.strip() + "," + ip_dest.strip() + "," + dest_port.strip() + "," + signature.strip() + "," + severity.strip() + "," + action.strip()
            else:
                var = timestamp[0] + " " + timestamp[1] + timestamp[2] + " " + timestamp[3] + "," + timestamp[4] + "," + juniper_type[3].strip() + "," + ip_src.strip() + "," + src_port.strip() + "," + ip_dest.strip() + "," + dest_port.strip() + "," + signature.strip() + "," + severity.strip() + "," + action.strip()       
            NumberOfP1IPs = NumberOfP1IPs + 1
            P1_IP_list.append(var)
      
    #SECOND LEVEL FILTER
    for item in P1_IP_list:
        if item.find("IDP_ATTACK") > -1 or item.find("SCREEN_TCP") > -1 or item.find("SCREEN_UDP") > -1:
            ip = item.split(",")
            ip = ip[3].strip()
            port = item.split(",")
            port = port[6].strip()
            
            Match = False
            for subitem in P1_IP_Unique:
                if subitem == ip:
                    Match = True
                    break;
                    
            if Match == False:
                if ip.count('.') == 3:
                    P1_IP_Unique.append(ip)
                    NumberOfAttackers = NumberOfAttackers + 1
                
            P1_Port_list.append(port)
            
            if ip.count('.') == 3:
                P1_Src_IP_list.append(ip)
        
        if item.find("IDP_ATTACK") > -1:
            signature = item.split(",")
            signature = signature[7].strip()
            P1_IDP_Signature_list.append(signature)
            
        if item.find("SCREEN_TCP") > -1 or item.find("SCREEN_UDP") > -1:
            signature = item.split(",")
            signature = signature[7].strip()
            P1_Screen_Signature_list.append(signature)
            
        if item.find("SCREEN_IP") > -1:
            signature = item.split(",")
            signature = signature[7].strip()
            P1_Screen_Signature_list.append(signature)

    #ANALYZE DESTINATION PORTS
    if EnableP1Report == True:
        P1_Port_Counter = collections.Counter(P1_Port_list)
        P1_Src_IP_list_Counter = collections.Counter(P1_Src_IP_list)
        P1_IDP_Signature_list_Counter = collections.Counter(P1_IDP_Signature_list)
        P1_Screen_Signature_list_Counter = collections.Counter(P1_Screen_Signature_list)

    st = (datetime.now()).strftime('%Y-%m-%d_%H%M%S')

    print("\n" + "juniper_srx_" + st + "_report.txt")

    f = open("juniper_srx_" + st + "_report.txt","w")

    if EnableCSVCreation == True:
        f1 = open("juniper_srx_" + st + "_report.csv","w")
        print("\n" + "juniper_srx_" + st + "_report.csv")
        f1.write("Timestamp" + "," + "Device" + "," + "Type" + "," + "SRC IP" + "," + "SRC PORT" + "," + "DEST IP" + "," + "DEST PORT" + "," + "Signature" + "," + "Severity" + "," + "Action" + "\n")
            
    print("\nNumber of {:s} Alerts {:d}\n".format(P1,NumberOfP1s))
    f.write("\nNumber of {:s} Alerts {:d}\n".format(P1,NumberOfP1s))

    for item in P1list:
        if EnableVerbosity == True:
            print(item) 
        f.write(item)

    print("\nNumber of {:s} Alerts Filtered {:d}\n".format(P1,NumberOfP1IPs))
    f.write("\nNumber of {:s} Alerts Filtered {:d}\n".format(P1,NumberOfP1IPs))

    for item in P1_IP_list:
        if EnableVerbosity == True:
            print(item)
        f.write(item + "\n")
        if EnableCSVCreation == True:
            f1.write(item + "\n")
        
    print("\nNumber of {:s} Alerts {:d}\n".format(P2,NumberOfP2s))
    print("Number of {:s} Alerts Allowed {:d}\n".format(P2,IDP_Allow))
    print("Number of {:s} Alerts Dropped {:d}\n".format(P2,IDP_Drop))

    f.write("\nNumber of {:s} Alerts {:d}\n".format(P2,NumberOfP2s))
    f.write("\nNumber of {:s} Alerts Allowed {:d}\n".format(P2,IDP_Allow))
    for item in P2list:
        if item.find("NONE") > -1:
            if EnableVerbosity == True:
                print(item)
            f.write(item)
            
    f.write("\nNumber of {:s} Alerts Dropped {:d}\n".format(P2,IDP_Drop))
    for item in P2list:
        if item.find("DROP") > -1:
            if EnableVerbosity == True:
                print(item)
            f.write(item)
        
    print("\nNumber of {:s} Alerts {:d}\n".format(P3,NumberOfP3s))
    f.write("\nNumber of {:s} Alerts {:d}\n".format(P3,NumberOfP3s))

    for item in P3list:
        if EnableVerbosity == True:
            print(item)
        f.write(item)
        
    print("\nNumber of {:s} Alerts {:d}\n".format(P4,NumberOfP4s))
    f.write("\nNumber of {:s} Alerts {:d}\n".format(P4,NumberOfP4s))

    for item in P4list:
        if EnableVerbosity == True:
            print(item)
        f.write(item)
        
    print("\nNumber of {:s} Alerts {:d}\n".format(P5,NumberOfP5s))
    f.write("\nNumber of {:s} Alerts {:d}\n".format(P5,NumberOfP5s))

    for item in P5list:
        if EnableVerbosity == True:
            print(item)
        f.write(item)

    print("\nNumber of {:s} Alerts {:d}\n".format(P8,NumberOfP8s))
    f.write("\nNumber of {:s} Alerts {:d}\n".format(P8,NumberOfP8s))

    for item in P8list:
        if EnableVerbosity == True:
            print(item)
        f.write(item)
        
    print("\nNumber of {:s} Session Denials {:d}\n".format(P9,NumberOfP9s))
    f.write("\nNumber of {:s} Session Denials {:d}\n".format(P9,NumberOfP9s))

    for item in P9list:
        if EnableVerbosity == True:
            print(item)
        f.write(item)
        
    print("\nNumber of {:s} Alerts {:d}\n".format(P6,NumberOfP6s))
    print("Number of {:s} Alerts Permitted {:d}\n".format(P6,SECINTEL_Permit))
    print("Number of {:s} Alerts Blocked {:d}\n".format(P6,SECINTEL_Block))

    f.write("\nNumber of {:s} Alerts {:d}\n".format(P6,NumberOfP6s))
    f.write("\nNumber of {:s} Alerts Permitted {:d}\n".format(P6,SECINTEL_Permit))
    for item in P6list:
        if item.find("PERMIT") > -1:
            if EnableVerbosity == True:
                print(item)
            f.write(item)
            
    f.write("\nNumber of {:s} Alerts Blocked {:d}\n".format(P6,SECINTEL_Block))
    for item in P6list:
        if item.find("BLOCK") > -1:
            if EnableVerbosity == True:
                print(item)
            f.write(item)
        
    print("\nNumber of {:s} Alerts {:d}\n".format(P7,NumberOfP7s))
    print("Number of {:s} Alerts Permitted {:d}\n".format(P7,AAMW_Permit))
    print("Number of {:s} Alerts Blocked {:d}\n".format(P7,AAMW_Block))

    f.write("\nNumber of {:s} Alerts {:d}\n".format(P7,NumberOfP7s))
    f.write("\nNumber of {:s} Alerts Permitted {:d}\n".format(P7,AAMW_Permit))
    for item in P7list:
        if item.find("PERMIT") > -1:
            if EnableVerbosity == True:
                print(item)
            f.write(item)
            
    f.write("\nNumber of {:s} Alerts Blocked {:d}\n".format(P7,AAMW_Block))
    for item in P7list:
        if item.find("BLOCK") > -1:
            if EnableVerbosity == True:
                print(item)
            f.write(item)

    print("\nNumber of Attackers {:d}\n".format(NumberOfAttackers))
    f.write("\nNumber of Attackers {:d}\n".format(NumberOfAttackers))

    if EnableVerbosity == True:
        print("\nList Of Attackers\n")
    f.write("\nList Of Attackers\n")
         
    for item in P1_IP_Unique:
        if EnableVerbosity == True:
            print(item)
        f.write(item + "\n")

    f.write("\nTop 50 Destination Ports\n")
    f.write("Port               Count\n")
    f.write("------------------------\n")

    for port, count in P1_Port_Counter.most_common(50):
        f.write("{:5s}          {:7d}\n".format(port, count))
        
    f.write("\nTop 50 Source IP Destinations\n")
    f.write("Address                  Count\n")
    f.write("------------------------------\n")

    for ip, count in P1_Src_IP_list_Counter.most_common(50):
        f.write("{:15s}        {:7d}\n".format(ip, count))
        
    f.write("\nTop 50 IDP Signatures\n")
    f.write("Signature                                      Count\n")
    f.write("----------------------------------------------------\n")

    for signature, count in P1_IDP_Signature_list_Counter.most_common(50):
        f.write("{:35s}          {:7d}\n".format(signature, count))
        
    f.write("\nTop 50 Screens Signatures\n")
    f.write("Signature                                      Count\n")
    f.write("----------------------------------------------------\n")

    for signature, count in P1_Screen_Signature_list_Counter.most_common(50):
        f.write("{:35s}          {:7d}\n".format(signature, count))
        
    if EnableNmapScan == True:
        print("\n{:s} NMAP Results ...\n".format(P1))
        f.write("\n{:s} NMAP Results ...\n".format(P1))

        for item in P1_IP_Unique:
            f.write(item + "\n")
            
            command_line = "nmap --script ip-geolocation-* " + item
            print(command_line)
            args = shlex.split(command_line)
            time.sleep(1)

            try:
                ret = subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            except OSError as e:
                print(e.strerror)
            except ValueError as e:
                print(e.strerror)
            else:
                (stdout_value,stderr_value) = ret.communicate()
                stderr_value = stderr_value.decode()
                return_value = ret.returncode
                
                my_output_list = (stdout_value.decode()).split("\n")
                    
                for line in my_output_list:
                    print(line)
                    f.write(line + "\n")
        
    f.close()

    if EnableCSVCreation == True:
        f1.close()

    #GET END TIME
    end_time = datetime.now()
    print("\nEND TIME: {}".format(end_time.strftime("%m/%d/%Y %H:%M:%S.%f")))

    print("\nDURATION: %d seconds" % ( (end_time-start_time).seconds) )

if __name__ == '__main__':
    main()
        
