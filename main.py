import json
from datetime import datetime
import ipaddress

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
with open("eve.json","r") as f:
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
for line in data:
	timestamps.append(line["timestamp"])
	try:
		if is_private_ip(line["src_ip"]):
			private_ips.append(line["src_ip"])
		if is_private_ip(line["dest_ip"]):
			private_ips.append(line["dest_ip"])
	except:
		continue
	if line["event_type"]=="dns":
		if "windows" in line["dns"]["rrname"]:
			windows_domains.append(line["dns"]["rrname"])
	if line["event_type"]=="flow":
		if is_private_ip(line["src_ip"]):
			services.append((line["app_proto"],"port : " + str(line["dest_port"])))

	try:
		if line["event_type"]=="alert":
			signatures.append(line["alert"]["signature"])
			malwares.append(line["alert"]["metadata"]["malware_family"])
			if "tls" in line:
				iocs.append((line["dest_ip"],line["tls"]["sni"]))
			if "dns" in line:
				iocs.append((line["dest_ip"],line["dns"]["query"][0]["rrname"]))
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
#q3
print(set(windows_domains))

file.write("Windows domains :  \n")
for domain in set(windows_domains):
	file.write(domain + "\n")

#q6
print(set(services))

file.write("THREAT DETECTION \n\n")
#q0
print(set(signatures))
file.write("Signatures detected : \n")
for sign in set(signatures):
	file.write(sign + "\n")
#q1
print((malwares))

#q2
print(set(iocs))

