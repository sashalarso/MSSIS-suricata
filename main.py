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

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

data=[]
with open(sys.argv[1],"r") as f:
	for line in f:
		
		data.append(json.loads(line))
		
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
for line in data:
	timestamps.append(line["timestamp"])
	try:
		if is_private_ip(line["src_ip"]):
			private_ips.append(line["src_ip"])
		if is_private_ip(line["dest_ip"]):
			private_ips.append(line["dest_ip"])
	except:
		continue
	try:
		if line["event_type"]=="dns":
			if "windows" in line["dns"]["rrname"] or "microsoft" in line["dns"]["rrname"]:
				windows_domains.append(line["dns"]["rrname"])
		if line["event_type"]=="flow":
			if is_private_ip(line["src_ip"]) and line["app_proto"]!="failed":

				services.append((line["app_proto"],"port : " + str(line["dest_port"])))
	except:
		continue
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
	try:
		if line["event_type"]=="krb5":
			if "cname" in line["krb5"] and line["krb5"]["cname"]!="<empty>":
				users.append(line["krb5"]["cname"])
				
	except:
		continue
	try:
		if line["event_type"]=="alert":
			signatures.append(line["alert"]["signature"])
			malwares.append(line["alert"]["metadata"]["malware_family"][0])
			if "tls" in line and line["dest_ip"] not in set(private_ips):
				iocs.append((line["dest_ip"],line["tls"]["sni"]))
			if "dns" in line and line["dest_ip"] not in set(private_ips):
				iocs.append((line["dest_ip"],line["dns"]["query"][0]["rrname"]))
	except:
		continue
	try:
		if line["event_type"]=="alert":
			if line["src_ip"] in private_ips: 
				impacted_adresses.append(line["src_ip"])
			if line["dest_ip"] in private_ips:
				impacted_adresses.append(line["dest_ip"])
	except:
		continue

sorted_timestamps=sorted(timestamps, key=extract_timestamp_key)

file=open("report.txt","w")
#q0
print(format_date(sorted_timestamps[0]))
print(format_date(sorted_timestamps[-1]))

file.write("First timestamp : " + format_date(sorted_timestamps[0]) + "\n")
file.write("Last timestamp : " + format_date(sorted_timestamps[-1]) + "\n\n")

#q1
print(set(private_ips))	

file.write("Private IPs : \n")
for p_ip in set(private_ips):
	file.write(p_ip + "\n")

#q2
file.write("\n")
ips=[]
print(trouver_reseau_commun(set(private_ips)))
#q3
print(set(windows_domains))

file.write("Windows domains :  \n")
for domain in set(windows_domains):
	file.write(domain + "\n")

#q4
print(set(users))
file.write("Users : \n")
for user in set(users):
	file.write(user + "\n")
file.write("\n")
#q5
print(set(os))
file.write("OS : \n")
for op in set(os):
	file.write(op + "\n")
file.write("\n")
#q6
print(set(services))
file.write("Services : \n")
for service in set(services):
	file.write(service[0] + " " + service[1] + "\n")


file.write("THREAT DETECTION \n\n")
#q0
print(set(signatures))
file.write("Signatures detected : \n")
for sign in set(signatures):
	file.write(sign + "\n")
#q1
print((malwares))
file.write("\n")
file.write("Malwares detected : \n")
for malware in set(malwares):
	file.write(malware + "\n")
print("\n")

#q2
file.write("\n")
file.write("Private adresses impacted : \n")
print(impacted_adresses)
for adresses in set(impacted_adresses):
	file.write(adresses + "\n")
print("\n")
#q3
print(set(iocs))
file.write("IOCS impacted (hostname,ip) : \n")
for ioc in set(iocs):
	file.write(ioc[0] + " " + ioc[1] + "\n")

#q4


file.close()

pdf = FPDF()   

pdf.add_page()
pdf.set_font("Arial", size = 15)
file=open("report.txt","r")
for x in file:
    pdf.cell(200, 10, txt = x, ln = 1, align = 'C')
pdf.output("report.pdf")  

