import json
from datetime import datetime
import ipaddress
from fpdf import FPDF
import sys


if len(sys.argv)<2:
	print("Usage python3 main.py <json_file>")
	sys.exit(1)


def format_date(date):
	date_object = datetime.strptime(date, "%Y-%m-%dT%H:%M:%S.%f%z")	
	formatted_date = date_object.strftime("%A, %d %B %Y %H:%M:%S %Z")
	return formatted_date

def extract_timestamp_key(timestamp):
    return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")

def is_private_ip(ip_address):
    
    ip_parts = ip_address.split('.')
    
    if len(ip_parts) != 4:
        return False
   
    ip_parts = [int(part) for part in ip_parts]
   
    if (ip_parts[0] == 10) or \
       (ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31) or \
       (ip_parts[0] == 192 and ip_parts[1] == 168):
        return True
    else:
        return False

data=[]
if str(sys.argv[1]).endswith(".json"):
	with open(sys.argv[1],"r") as f:
		for line in f:
			
			data.append(json.loads(line))
else:
	print("Please pass a json file as argument")
	sys.exit(1)


#variables initialisation		
timestamps=[]
private_ips=[]
windows_domains=[]
malwares=[]
signatures=[]
iocs=[]
services=[]
impacted=[]
users=[]
os=[]
impacted_adresses=[]
domain_ctl=[]
hashes=[]
#iterate over the json
for line in data:
	#q0 load timestamps
	timestamps.append(line["timestamp"])

	#q1 get private ips
	try:
		if is_private_ip(line["src_ip"]):
			private_ips.append(line["src_ip"])
		if is_private_ip(line["dest_ip"]):
			private_ips.append(line["dest_ip"])
	except:
		continue

	try:
		#q3 get dns domains and domain controllers
		if line["event_type"]=="dns":
			#get windows domains
			if "windows" in line["dns"]["rrname"] or "microsoft" in line["dns"]["rrname"]:
				windows_domains.append(line["dns"]["rrname"])
			#domain controller is what is in name if rrtype is SRV
			if "rrname" in line["dns"]:
				if line["dns"]["rrtype"]=="SRV":
					domain_ctl.append(line["dns"]["answers"][0]["srv"]["name"])
		#q6 get all protos in the network, check also if proto is TCP
		if line["event_type"]=="flow":
			if is_private_ip(line["src_ip"]) and line["app_proto"]!="failed":
				if line["proto"]=="TCP":
					services.append((line["app_proto"],"port : " + str(line["dest_port"])))
	except:
		continue
	#q4-5 get users and os in smb requests
	try:
		if line["event_type"]=="smb":
			if "ntlmssp" in line["smb"]:
				if line["smb"]["ntlmssp"]["user"]!="":
					users.append(line["smb"]["ntlmssp"]["user"])
				if "response" in line["smb"]:
					
					if line["smb"]["response"]["native_os"]!="":
						os.append(line["smb"]["response"]["native_os"])
	except:
		continue
	#q4 get users in krb5 requests
	try:
		if line["event_type"]=="krb5":
			if "cname" in line["krb5"] and line["krb5"]["cname"]!="<empty>":
				users.append(line["krb5"]["cname"])
				
	except:
		continue
	#threat detection
	try:
		
		if line["event_type"]=="alert":
			#q0
			signatures.append(line["alert"]["signature"])
			#q1
			if "malware_family" in line["alert"]["metadata"]:
				malwares.append(line["alert"]["metadata"]["malware_family"][0])
			#q3
			if "tls" in line and line["dest_ip"] not in set(private_ips):
				
				iocs.append((line["dest_ip"],line["tls"]["sni"]))
			if "tls" in line and line["src_ip"] not in set(private_ips):
				iocs.append((line["src_ip"],line["tls"]["sni"]))
			if "http" in line and line["dest_ip"] not in set(private_ips):
				
				iocs.append((line["dest_ip"],line["http"]["hostname"]))
			if "http" in line and line["src_ip"] not in set(private_ips):
				iocs.append((line["src_ip"],line["http"]["hostname"]))
	except:
		continue
		
	#q2 load ip adresses from alert events
	try:
		if line["event_type"]=="alert":
			if line["src_ip"] in private_ips: 
				impacted_adresses.append(line["src_ip"])
			if line["dest_ip"] in private_ips:
				impacted_adresses.append(line["dest_ip"])
	except:
		continue
	#q4 get flow id from alert events, check if flow ids from alert events are present in fileinfo event and get sha256
	try:
		if line["event_type"]=="alert":
			flow_id=line["flow_id"]
			
			for sub in data:
				if sub["flow_id"]==flow_id and sub["event_type"]=="fileinfo":
					
					if "fileinfo" in sub:
						hashes.append(sub["fileinfo"]["sha256"])
	except:
		continue

#sort timestamps to get first and last
sorted_timestamps=sorted(timestamps, key=extract_timestamp_key)

#write report
file=open("report.txt","w")
file.write("For file " + sys.argv[1])
file.write("\n")

#q0

file.write("First timestamp : " + format_date(sorted_timestamps[0]) + "\n")
file.write("Last timestamp : " + format_date(sorted_timestamps[-1]) + "\n\n")

#q1

file.write("Private IPs : \n")
for p_ip in set(private_ips):
	file.write(p_ip + "\n")

#q2
file.write("\n")

file.write("Networks : \n")
networks=[]
for ip in set(private_ips):
	ipa=ip.split(".")
	
	if ipa[0]=="10":
		networks.append("10.0.0.0/8")
	elif ipa[0]=="172" and (int(ip[1])>=16 or int(ip[1])<=31):
		networks.append("172.16.0.0/12")
	elif int(ipa[0])=="192" and int(ipa[1])=="168":
		networks.append("192.168.0.0/16")
for ip in set(networks):
	file.write(ip + "\n")
file.write("\n")
#q3


file.write("Windows domains :  \n")
for domain in set(windows_domains):
	file.write(domain + "\n")
file.write("\n")
file.write("Domain controllers :  \n")
for domain in set(domain_ctl):
	file.write(domain + "\n")
#q4

file.write("\n")
file.write("Users : \n")
for user in set(users):
	file.write(user + "\n")
file.write("\n")
#q5

file.write("OS : \n")
for op in set(os):
	file.write(op + "\n")
file.write("\n")
#q6

file.write("Services TCP/IP : \n")
for service in set(services):
	file.write(service[0] + " " + service[1] + "\n")


file.write("THREAT DETECTION \n\n")
#q0

file.write("Signatures detected : \n")
for sign in set(signatures):
	file.write(sign + "\n")
#q1

file.write("\n")
file.write("Malwares detected : \n")
for malware in set(malwares):
	file.write(malware + "\n")


#q2
file.write("\n")
file.write("Private adresses impacted : \n")

for adresses in set(impacted_adresses):
	file.write(adresses + "\n")

#q3

file.write("\n")
file.write("IOCS concerned (hostname,ip) : \n")
for ioc in set(iocs):
	file.write(ioc[0] + " " + ioc[1] + "\n")

#q4
file.write("\n")
file.write("Hashes detected : \n")
for hash in set(hashes):
	file.write(hash + "\n")

file.close()

#convert txt to pdf
pdf = FPDF()   

pdf.add_page()
pdf.set_font("Arial", size = 15)
file=open("report.txt","r")
for x in file:
    pdf.cell(200, 10, txt = x, ln = 1, align = 'C')
pdf.output("report.pdf")  

print("Report wrote in report.pdf/.txt")

