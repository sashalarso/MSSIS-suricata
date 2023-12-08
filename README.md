This program takes an eve.json file(output of suricata) as input and writes a small report in pdf and txt.

Infos wrote in the report:
-first and last timestamp
-private ips
-networks
-windows domain names
-users
-os of users
-tcp/IP services in the private networks
-unique signatures of alerts
-private ips impacted by alerts
-malwares detected
-iocs concerned by alerts
-sha256 of detected files in alerts


To be able to run the program execute the following command : ```python3 -m pip install -r requirements.txt```

To run the program enter : ```python3 main.py <json_file>```