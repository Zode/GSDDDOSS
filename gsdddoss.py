import sys, os
isLinux = False
if sys.platform == "linux" or sys.platform == "linux2":
	isLinux = True
	
import re
import subprocess
import json
import socket

if not isLinux:
	import ctypes
	def is_admin():
		try:
			return ctypes.windll.shell32.IsUserAnAdmin()
		except:
			return False
else:
	def is_admin():
		user = os.getenv("SUDO_USER")
		if user is None:
			return False
		else:
			return True


		
if not is_admin():
	print("This script requires python to be run as administrator!")
	print("Otherwise no changes can be made to the firewall.")
	sys.exit(0)
	
if not os.path.isfile("ips.json"):
	print("Missing .json file!\n")
	print("Please create a file named \"ips.json\" in the script's directory")
	print("with the contents: {\"banned\": []}")
	sys.exit(0)

def config_save(data, conf):
	with open(conf+".json", "w", encoding="utf-8") as f:
		json.dump(data, f)
		
def config_load(conf):
	with open(conf+".json", "r", encoding="utf-8") as f:
		return json.load(f)
	
class badip:
	def __init__(self, ip, port):
		self.ip = ip
		self.port = port

def regex(incoming, pattern):
	regsearch = re.search(r"{}".format(pattern), incoming, re.I)
	if(regsearch):
		return badip(regsearch.group(1), regsearch.group(2))
	else:
		return None
		
def getall(ip):
	ret = ip
	for storedip in main_config["banned"]:
		ret = ret+",{}".format(storedip)
		
	return ret
		
def blockip(ip): #Make one rule per IP, used to group IPs in windows but it quickly hit the firewall rule limitation.
	if isLinux:
		subprocess.call("iptables -A INPUT -s {} -j DROP".format(ip), shell=True)
	else:
		subprocess.call("netsh advfirewall firewall add rule name=\"Blocked IP\" dir=in interface=any action=block remoteip={}".format(ip), shell=True)
		
	main_config["banned"].append(ip)
	print("Blocked ip: "+ip)
	config_save(main_config, "ips")

main_config = config_load("ips")
iplist = {}
hotlist = {}

def count_ports(input, match):
	ret = 0
	for inp in input:
		if inp == match:
			ret = ret+1
			
	return ret

#hacky udp loop
def udp_server(host="127.0.0.1", port=8008):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	print("Udp started: {}:{}".format(host, port))
	print("INFINITE LOOP; ^C WILL MOST LIKELY NOT WORK!")
	s.bind((host,port))
	while True:
		(data, addr) = s.recvfrom(128*1024)
		yield data[4:-1].decode("utf-8") # has garbag header + ending

for data in udp_server():
	ret = regex(data, "([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)\swas\sblocked\sfor\sexceeding\srate\slimits$")
	if(ret != None):
		if ret.ip not in main_config["banned"]:
			if ret.ip in iplist:
				iplist[ret.ip].append(ret.port)
				counted = count_ports(iplist[ret.ip], ret.port)
				if(counted >= 3):
					print("Found a naughty ip: {} (rate limit, repeating port was: {})".format(ret.ip, ret.port))
					blockip(ret.ip)
					if ret.ip in hotlist:
						hotlist.pop(ret.ip)
						
					iplist.pop(ret.ip)
					
				if(counted <= 1 and len(iplist[ret.ip]) > 12):
					print("Popping: {} (most likely valid person spamming browser refresh)".format(ret.ip))
					if ret.ip in hotlist:
						hotlist[ret.ip].append(ret.port)
						if len(hotlist[ret.ip]) > 3:
							print("Found a naughty ip: {} (rate limit, port blasting)".format(ret.ip))
							hotlist.pop(ret.ip)
							blockip(ret.ip)
					else:
						hotlist[ret.ip] = []
						hotlist[ret.ip].append(ret.port)
						
					iplist.pop(ret.ip)
			else:
				iplist[ret.ip] = []
				iplist[ret.ip].append(ret.port)
				
	ret = regex(data, "^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)\stried\sto\ssend\ssplit\spacket")
	if(ret != None):
		if ret.ip not in main_config["banned"]:
			print("Found extremely naughty ip: {} (SPLIT PACKET!)".format(ret.ip))
			blockip(ret.ip)
			
	ret = regex(data, "Bad\sRcon:\s(?:.*)\sfrom\s\"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)\"")
	if(ret != None):
		if ret.ip not in main_config["banned"]:
			print("Found semi-naughty ip: {} (bad rcon)".format(ret.ip))
			blockip(ret.ip)