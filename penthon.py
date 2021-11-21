#!/usr/bin/python3.7
import os
import fire
import subprocess
import struct
from terminaltables import SingleTable
import socket
import uuid
import re
import requests
from string import ascii_uppercase, ascii_lowercase, digits
import binascii
from scapy.all import *
import netifaces
import random
import command
import json
from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter
from huepy import *
import netaddr
import ipaddress
import struct

def p8(x: int, s: bool = False): return struct.pack("<B",x) if not s else struct.pack("<b",x)
def p16(x: int, s: bool = False): return struct.pack("<H",x) if not s else struct.pack("<h",x)
def p32(x: int, s: bool = False): return struct.pack("<I",x) if not s else struct.pack("<i",x)
def p64(x: int, s: bool = False): return struct.pack("<Q",x) if not s else struct.pack("<q",x)
def u8(x: bytes, s: bool = False): return struct.unpack("<B",x)[0] if not s else struct.unpack("<b",x)[0]
def u16(x: bytes, s: bool = False): return struct.unpack("<H",x)[0] if not s else struct.unpack("<h",x)[0]
def u32(x: bytes, s: bool = False): return struct.unpack("<I",x)[0] if not s else struct.unpack("<i",x)[0]
def u64(x: bytes, s: bool = False): return struct.unpack("<Q",x)[0] if not s else struct.unpack("<q",x)[0]

def pack_little_endian(string):
	"""
	Packs an integer in little endian
	"""
	return struct.pack('<I', string)

def pack_big_endian(string):
	"""
	Packs an integer in big endian
	"""
	return struct.pack('>I', string)

def pack_network(string):
	"""
	Packs an integer in network byte order 
	"""
	return struct.pack('!I', string)

def print_info(msg):
	"""
	Prints info message
	"""
	print(f"[*] {msg}")

def print_error(msg):
	"""
	Prints error message
	"""
	print(f"{red('[x]')} {msg}")

def print_good(msg):
	"""
	Prints good message
	"""
	print(f"{green('[+]')} {msg}")

def nops(len):
	"""
	Returns a nopsled of given length
	"""
	return '\x90' * len

def nops_generator(length):
	"""
	Generates a non-canonical nopsled of desired length
	"""
	nops = ['\x41\x49', '\x40\x48', '\x42\x4A', '\x43\x4B', '\x44\x4C'
			'\x45\x4D', '\x46\x4E', '\x47\x4F', '\x50\x58', '\x51\x59',
			'\x52\x5A', '\x53\x5B', '\x54\x5C', '\x55\x5D', '\x56\x5E',
			'\x57\x5F', '\x61\x60']

	nopsled = ''
	for l in range(0,length/2):
			nopsled += nops[random.choice(range(0,len(nops)))]
	if length % 2 != 0:
			nopsled += '\x90'
	return nopsled

def kill_pid(pid):
	"""
	Kills a process by PID
	"""
	try:
		os.kill(pid, 0)
	except OSError:
		return False
	else:
		return True

def channel_hopper(iface):
	"""
	Performs channel switching of a given network interface in an infinite loop
	"""
	while True:
		channel = random.randrange(1,15)
		os.system(f"iw dev {iface} set channel {channel}")
		time.sleep(1)

def sizeof_fmt(b, suffix='B'):
	"""
	Retoorns a humen-readebl no. of bites from the within of a specially formatted amount string that MUST END with a character or character pair specified within unit list
	"""
	for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
		if abs(b) < 1024.0:
			return "%3.1f%s%s" % (b, unit, suffix)
		b /= 1024.0
	return "%.1f%s%s" % (b, 'Yi', suffix)

def parse_time(entry): 
	"""
	Converts given interval to seconds
	"""
	num = int(entry[:-1])
	period = entry[-1]
	if period == "s":
		seconds = num
	elif period == "m":
		seconds = num * 60
	elif period == "h":
		seconds = num * 3600
	return seconds

def ifaces():
	"""
	Returns a list of currently active network interfaces
	"""
	ifaces = []
	dev = open('/proc/net/dev', 'r')
	data = dev.read()
	for facecard in re.findall('[a-zA-Z0-9]+:', data):
	   ifaces.append(facecard.rstrip(":"))
	dev.close()
	return ifaces

def local_ip():
	"""
	Returns a local ip address of the current subnet
	"""
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8", 80))
	return s.getsockname()[0]

def global_ip():
	"""
	Returns an internet facing ip address of the host
	"""
	return requests.get('https://api.ipify.org').text

def mac():
	"""
	Returns a hardware interface address of the current host
	"""
	return ":".join(["{:02x}".format((uuid.getnode() >> ele) & 0xff)
		for ele in range(0,8*6,8)][::-1])

def get_mac(ip):
	"""
	Returns a MAC address of a given IP address
	"""
	conf.verb = 0
	ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=10)
	for s,r in ans:
		return r.src

def port_forward(s_port, d_port):
	"""
	Forwards a local port
	"""
	try:
		ip = self.local_ip()
		cmd_run('iptables -A PREROUTING -t nat -i eth0 -p tcp --dport {} -j DNAT --to {}:{}'.format(s_port,ip,d_port))
		cmd_run('iptables -A FORWARD -p tcp -d {} --dport {} -j ACCEPT'.format(ip,d_port))
		print_info('Forwarded traffic from {}:{} to port {}'.format(ip,s_port,d_port))
	except:
		print_error("Cannot perform port forwarding")

def is_port_open(host, port): 
	"""
	Checks if a remote port is open
	"""
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	res = s.connect_ex((host, port))
	if res == 0:
		return True
	else:
		return False

def ip_to_hex(ip):
	"""
	Converts a quad-dotted IP address to hex
	"""
	ip = binascii.hexlify(socket.inet_aton(ip))
	return '0x'+'0x'.join([''.join(x) for x in zip(*[list(ip[z::2]) for z in range(2)])])

def hex_to_ip(self, hex):
	"""
	Converts IP in hex format to quad-dotted
	"""
	addr = socket.inet_ntoa(hex)
	return addr

def cmd_out(cmd):
	"""
	Executes a command and returns it's output
	"""
	proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
	out, err = proc.communicate()
	return out.rstrip().decode('utf-8')

def chunk_split(s, count):
	"""
	Splits a string to a chunks of desired length each
	"""
	print([''.join(x) for x in zip(*[list(s[z::count]) for z in range(count)])])

def int_to_hex(integer, endian='little'):
	"""
	Converts integer to hex
	"""
	if endian == 'little':
		en = '<I'
	elif endian == 'big':
		en = '>I'
	hx = ''.join(x.encode('hex') for x in struct.pack(en, integer)).replace('00', '')
	hx = ''.join([binascii.unhexlify(op) for op in chunk_split(hx,2)])
	return hx

def remove_chars(string, chars):
	"""
	Fully removes a given character set from a string
	"""
	for chr in chars:
		string = string.replace(chr, '')
	return string

def print_standard_table(table_data, title=None):
	"""
	Prints a boring ASCII table
	"""
	table_instance = SingleTable(table_data) 
	table_instance.inner_heading_row_border = True
	table_instance.inner_row_border = False
	table_instance.title = title
	table_instance.justify_columns = {0: 'left', 1: 'left', 2: 'left'}
	print(table_instance.table)

def print_msf_table(table_data):
	"""
	Prints a metasploit-styled ASCII table
	"""
	styles = []
	for title in table_data[0]:
		msf_style = "-"*len(title)
		styles.append(msf_style)
	table_data.insert(1, styles)
	table_instance = SingleTable(table_data) 
	table_instance.inner_heading_row_border = False
	table_instance.inner_row_border = False
	table_instance.inner_column_border = False
	table_instance.outer_border = False
	table_instance.justify_columns = {0: 'left', 1: 'left', 2: 'left'}
	print(table_instance.table)
	print('')

def print_titled_field(table_data, title):
	"""
	Prints a single string in a one-cell enclosure
	"""
	table_instance = SingleTable(table_data) 
	table_instance.inner_heading_row_border = True
	table_instance.inner_row_border = False
	table_instance.title = title
	table_instance.justify_columns = {0: 'left', 1: 'left', 2: 'left'}
	print(table_instance.table)

def ap_essid():
	"""
	Returns a name of currently connected wifi AP
	"""
	p = subprocess.Popen(["iwconfig"], stdout=subprocess.PIPE)
	output = p.communicate()[0].decode("utf-8")
	essid = re.search('ESSID:"(.*)"', output).group(1)
	return essid

def ap_bssid():
	"""
	Returns a MAC address of currently connected wifi AP
	"""
	gateway_ip = netifaces.gateways()['default'][2][0]
	return get_mac(gateway_ip)

def ap_ip():
	"""
	Returns an IP address of the gateway
	"""
	return netifaces.gateways()['default'][2][0]

def lookup_dns(name):
	"""
	Get DNS record from the server
	"""
	return socket.gethostbyaddr(ip_address)[-1][0]

def lookup_rdns():
	"""
	Reverse DNS lookup
	"""
	return socket.gethostbyaddr(ip_address)[0]

def banner_grab(host, port):
	"""
	Gain information about a computer system on a network and the services running on its open ports
	"""
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((self.opt.RHOST, self.opt.RPORT))
		return s.recv(4096)
	except:
		pass

#TODO: return current_iface, ifaces[]
def get_interfaces():
	"""
	Get simplified list of interfaces
	"""
	p = subprocess.Popen(["ifconfig"], stdout=subprocess.PIPE)
	output = p.communicate()[0].decode("utf-8")
	ifaces = re.findall("(.*): flags", output)
	return ifaces

def get_interfaces_full():
	"""
	Get full list of interfaces
	"""
	result = {}
	index = 0
	for i in get_if_list():
		if isinstance(i, str):
			name = i
		elif isinstance(i, dict):
			name = i['name']
		else:
			return {}
		result[name] = { 'name' : name, 'index' : index }
		result[name]['mac'] = get_if_hwaddr(name)
		if not result[name]['mac']:
			result[name]['mac'] = None
		result[name]['inet'] = None
		for route in conf.route.routes:
			if getattr(route[3], 'name', route[3]) == name:
				result[name]['inet'] = route[4]
				break
		result[name]['inet6'] = None
		for route in conf.route6.routes:
			if getattr(route[3], 'name', route[3]) == name:
				result[name]['inet6'] = route[4][0]
				break
		index += 1
	return result

def search_interface(term):
	"""
	Search through interfaces
	"""
	if not term:
		return None
	for iface in get_interfaces_full().values():
		if term in iface.values():
			return iface
		if str(term) == str(iface['index']):
			return iface
	return None

def run_bg(func_name, args=()):
	"""
	Run process in background
	"""
	if len(args) == 0:
		new_thread = threading.Thread(target=func_name)
	else:
		new_thread = threading.Thread(target=func_name, args=args)
	new_thread.start()

def ip_bit_len(mask):
	"""
	Get IP bit length
	"""
	return "".join(bin(m)[2:] for m in mask).find('0')
 
def ip_prefix(mask, ip):
	"""
	Get IP prefix from mask
	"""
	return ".".join(str(m & i) for m, i in zip(mask, ip))
 
def cidr(mask, ip):
	"""
	Return CIDR addresses
	"""
	mask = int_address(mask)
	ip = int_address(ip)
	return ip_prefix(mask, ip)+"/"+str(ip_bit_len(mask))

def ip2cidr(ip_addr):
	"""
	Convert IP to CIDR specification
	"""
	ip_splitted = ip_addr.split(".")
	ip_splitted[-1] = "0" 
	start_addr = ".".join(ip_splitted)
	ip_splitted[-1] = "255"
	end_addr = ".".join(ip_splitted)
	return str(netaddr.iprange_to_cidrs(start_addr, end_addr)[0].cidr)

def pattern_gen(length):
	"""
	Generate a pattern of a given length up to a maximum
	of 20280 - after this the pattern would repeat
	"""
	MAX_PATTERN_LENGTH = 20280
	if length >= MAX_PATTERN_LENGTH:
		raise MaxLengthException('ERROR: Pattern length exceeds maximum of %d' % MAX_PATTERN_LENGTH)

	pattern = ''
	for upper in ascii_uppercase:
		for lower in ascii_lowercase:
			for digit in digits:
				if len(pattern) < length:
					pattern += upper+lower+digit
				else:
					out = pattern[:length]
					return out

def pattern_search(search_pattern):
	"""
	Search pattern
	"""
	needle = search_pattern
	try:
		if needle.startswith('0x'):
			# Strip off '0x', convert to ASCII and reverse
			needle = needle[2:]
			needle = bytearray.fromhex(needle).decode('ascii')
			needle = needle[::-1]
	except (ValueError, TypeError) as e:
		raise
	haystack = ''
	f = None
	for upper in ascii_uppercase:
		for lower in ascii_lowercase:
			for digit in digits:
				haystack += upper+lower+digit
				found_at = haystack.find(needle)
				if found_at > -1:
					f = found_at
	return f


def ip_to_hex(ip):
	"""
	Convert IP to hex
	"""
	#segments = ip.split('.')[::-1]
	#hex_ip = "0x"
	#for segment in segments:
	#    if int(segment) in range(0, 16):
	#        hex_ip += "0" + hex(int(segment)).replace("0x", "")
	#    else:
	#        hex_ip += hex(int(segment)).replace('0x', '')
	#if not raw:
		#return remove_chars(str(binascii.hexlify(socket.inet_aton(ip))), ["'", "b"])
	return hex(struct.unpack('<L', socket.inet_aton(ip))[0])
	#else:
	#    return ''.join([binascii.hexlify(op) for op in chunk_split(remove_chars(hex_ip, "0x"), 2)])

def parse_keyval_opts(options_string, char="="):
	"""
	Parse key values from pair strings
	"""
	res_dict = {}
	key_value_pairs = options_string.split(" ")
	for pair in key_value_pairs:
		name = pair.split(char)[0]
		value = pair.split(char)[1]
		res_dict[name] = value
	return res_dict

def asm():
	"""
	Assembly file
	"""
	pass

def disasm():
	"""
	Disassembly given file
	"""
	pass

def random_insert(string, insertion):
	"""
	Insert random string
	"""
	pass

def random_int(start, stop, number_of_ints):
	"""
	Get random int
	"""
	random_list = []
	while number_of_ints:
		res = random.randint(start, stop)
		if res not in random_list:
			random_list.append(res)
		number_of_ints -= 1
	return random_list

def switch_bool(bool_val):
	"""
	Change bool value to the opposite one
	"""
	if bool_val:
		return not bool_val
	return bool_val

def load_modules_from_subdir(subdir):
	"""
	Load external Python modules as files from a given subdir
	"""
	payloads = []
	plds = []
	for p in os.walk(subdir): 
		payloads.append(p)
	payloads = payloads[0][2]
	for p in payloads:
		if ('init' in p or '.pyc' in p):
			pass
		else:
			plds.append(importlib.import_module(mod.replace(".py", '')))
	return plds

def cmd_out(command):
	"""
	Get cmd output from given command
	"""
	cmd_resp = command.core.Command().run([command])
	return cmd_resp.out.decode("utf-8")

def cmd_run(command):
	"""
	Run cmd
	"""
	#command.core.Command().run([command])
	os.system(f"{command} &")

def cmd_run_bg(command):
	"""
	Run cmd in background
	"""
	#command.core.Command().run([command])
	os.system(f"{command} &")

def cmd_run_bg_no_output(command):
	"""
	Run cmd in background without saved output
	"""
	#command.core.Command().run([command])
	os.system(f"{command} & 2>&1 > /dev/null")

def contains_any(src_str, iterable):
	"""
	Check if src contains given string
	"""
	if any(x in src_string for x in iterable):
		return True
	return False

def print_json(json_string):
	"""
	Print nice looking JSON string
	"""
	json_object = json.loads(json_string)
	json_str = json.dumps(json_object, indent=4, sort_keys=True)
	print(highlight(json_str, JsonLexer(), TerminalFormatter()))

def cat(filename):
	"""
	Read file
	"""
	return open(filename, "r+").read()

def ip_same_network(ip_1, ip_2):
	"""
	Check whether the IP addresses are in the same network
	"""
	a = ipaddress.ip_network(ip_1, strict = False).network_address
	b = ipaddress.ip_network(ip_2, strict = False).network_address
	if a == b:
		return True
	return False

# Full creditz for below three functions:
# https://github.com/hugsy/stuff/blob/master/pentestlib.py
def GET(url, headers={}, proxies={}):
	"""
	GET request data
	ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/GET
	"""
	headers["User-Agent"] = "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; fr-FR)"
	return requests.get(url, proxies=proxies, headers=headers, verify=False)

def POST(url, data={}, headers={}, proxies={}):
	"""
	POST method to create or add a resource on the server
	ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST
	"""
	headers["User-Agent"] = "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; fr-FR)"
	return requests.post(url, data=data, proxies=proxies, headers=headers, verify=False)

def TRACE(url, fwd_until=1, headers={}, proxies={}):
	"""
	Probe proxy presence through TRACE method
	ref: http://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html
	"""
	if fwd_until < 1:
		raise ValueError("Max-Forward value is too low")

	def do_trace(sess, max_forward):
		headers["User-Agent"] = "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; fr-FR)"
		headers["Max-Forwards"] = max_forward
		req = requests.Request("TRACE", url, headers=headers).prepare()
		return s.send(req, verify=False, proxies=proxies).headers

	response_headers = []
	s = requests.Session()
	for i in range(fwd_until):
		response_headers.append( do_trace(s, i) )

	return response_headers

if __name__ == "__main__":
	fire.Fire(X)
