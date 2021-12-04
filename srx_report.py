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

#RELEASE NOTES
#   DATE        VER         AUTHOR          DESCRIPTION
#   07-2021     1.0         MOOJIT          INITIAL RELEASE

MAJOR_VERSION = 1
MINOR_VERSION = 0

NumberOfP1s = 0
NumberOfP2s = 0
NumberOfP3s = 0
NumberOfP4s = 0
NumberOfP5s = 0
NumberOfP6s = 0

Match = False

EnableP1Report = True
EnableP2Report = True
EnableP3Report = True
EnableP4Report = True
EnableP5Report = True
EnableP6Report = False
EnableNmapScan = False
EnableCSVCreation = True
EnableVerbosity = False
CustomPath = False

P1 = "IDP ATTACK AND SCREENS"
P2 = "IDP ATTACK"
P3 = "SCREENS"
P4 = "SCREENS TCP"
P5 = "SCREENS UDP"
P6 = "P6"

P1list = []
P2list = []
P3list = []
P4list = []
P5list = []
P6list = []

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

print("\nJuniper SRX Report " + str(MAJOR_VERSION) + "." + str(MINOR_VERSION) + " ")

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
        f = open(path + file,"r")
        
        for line in f:
            if EnableP1Report == True:
                if line.find("IDP_ATTACK") > -1 or line.find("SCREEN") > -1:
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
            
            if EnableP3Report == True:
                if line.find("SCREEN") > -1:
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
                        
            if EnableP6Report == True:
                if line.find("FW-6") > -1:
                    Match = False
                    for item in P6list:
                        if item == line:
                            Match = True
                            break
                    
                    if Match == False:
                        NumberOfP6s = NumberOfP6s + 1
                        P6list.append(line)
        
        f.close

P1list.reverse()
P2list.reverse()
P3list.reverse()
P4list.reverse()
P5list.reverse()
P6list.reverse()

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

    elif line.find("SCREEN") > -1:
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
        action = line.split(":")
        action = action[11].strip()
        if len(timestamp[1]) > 1:
            var = timestamp[0] + " " + timestamp[1] + " " + timestamp[2] + "," + timestamp[3] + "," + juniper_type[3].strip() + "," + ip_src + "," + src_port + "," + ip_dest + "," + dest_port + "," + signature[0].strip() + "," + "," + action
        else:
            var = timestamp[0] + " " + timestamp[1] + timestamp[2] + " " + timestamp[3] + "," + timestamp[4] + "," + juniper_type[3].strip() + "," + ip_src + "," + src_port + "," + ip_dest + "," + dest_port + "," + signature[0].strip() + "," + "," + action
        NumberOfP1IPs = NumberOfP1IPs + 1
        P1_IP_list.append(var)
  
#SECOND LEVEL FILTER
for item in P1_IP_list:
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
        
    if item.find("SCREEN") > -1:
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
f.write("\nNumber of {:s} Alerts {:d}\n".format(P2,NumberOfP2s))

for item in P2list:
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
    
print("\nNumber of {:s} Alerts {:d}\n".format(P6,NumberOfP6s))
f.write("\nNumber of {:s} Alerts {:d}\n".format(P6,NumberOfP6s))

for item in P6list:
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
    f.write("{:15s}          {:7d}\n".format(ip, count))
    
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
        