#!/usr/bin/env python3

import os
import json
import socket
import requests
from cmd import Cmd
from bs4 import BeautifulSoup

class ipinfo_io():
	"""
	usage: IPInfo()._is_ip('127.0.0.1')
	>>> returns bool
	"""
	def _is_ip(self, ip):
		try:
			socket.inet_aton(ip)
			return True
		except:
			return False

	"""
	set iponly=1 if you only want to return the ip address exclusively
	usage: IPInfo().get_my_ip()
		   IPInfo().get_my_ip(1)
	>>> returns connected-client information
	"""
	def get_my_ip(self, iponly=0):
		try:
			r = requests.get("http://ipinfo.io/json")
			if(iponly == 1):
				return json.loads(r.text)['ip']
			else:
				return r.text
		except:
			return False

	"""
	usage: IPInfo().get_asn_of_ip('172.217.6.14')
	>>> returns asn of a given ip
	"""
	def get_asn_of_ip(self, ip):
		if(self._is_ip(ip)):
			r = requests.get("http://ipinfo.io/{0}/org".format(ip))
			return r.text.split(' ')[0]
		else:
			return False

	"""
	usage: IPInfo().get_asn('AS7765')
	>>> returns asn information
	"""
	def get_asn(self, target):
		retval = {}
		retval['summary'] = {}
		retval['whois'] = {}
		retval['ipblocks'] = []
		r = requests.get("http://ipinfo.io/{}".format(target))
		response = r.text.strip()
		# check to make sure the api has info on the given target
		if("Sorry, we couldn't find the page you requested!" in response):
			return False
		else:
			# parse the page because it refuses to return json results :(
			document = BeautifulSoup(response, "html.parser")
			td_elements = document.find_all('td')
			# assign summary values
			try:
				retval['summary']['asn'] = td_elements[1].string
				retval['summary']['allocated'] = td_elements[3].string
				retval['summary']['registry'] = td_elements[5].string
				retval['summary']['domain'] = td_elements[7].string
				retval['summary']['ips'] = td_elements[9].string
			except:
				return False
			# look for all <pre> tags
			pre_elements = document.find('pre').string.replace("\n\n", "")
			# assign whois values
			for line in pre_elements.splitlines():
				cleanline = line.replace(" ", "")
				cleanline = cleanline.split(':')
				retval['whois'][cleanline[0]] = cleanline[1]
			# look for all <a> tags
			# assign ipblocks values
			for a in document.find_all('a'):
				if("{0}".format(retval['summary']['asn']) in a['href']):
					ipblock = a['href'].replace("/{0}/".format(retval['summary']['asn']), '')
					retval['ipblocks'].append(ipblock)
			return retval

	"""
	usage: IPInfo().get_asn_ips('AS7765')
	>>> returns ips of the specified ipblocks 
	"""
	def get_asn_ips(self, asn):
		# grab asn info right away. gonna need it for ipblock iteration
		asn = self.get_asn(asn)
		retval = {}
		retval['ips'] = []
		try:
			if(len(asn['ipblocks']) > 1):
				# iterate through ipblocks & get every ipblock's ips
				for ipblock in asn['ipblocks']:
					r = requests.get("http://ipinfo.io/{0}/{1}".format(asn['summary']['asn'], ipblock))
					response = r.text.strip()
					document = BeautifulSoup(response, "html.parser")
					for a in document.find_all('a'):
						ip = a['href'].replace("/", "")
						# if entry is valid ip, then add to ips
						try:
							socket.inet_aton(ip)
							retval['ips'].append(ip)
						# otherwise pass
						except:
							pass
				return retval
		except:
			return False

	"""
	if no argument is given, it will return the connected-client's ip
	usage: IPInfo().get_ip('127.0.0.1')
	>>> return information on the given address
	"""
	def get_ip(self, ip=False):
		if(ip):
			if(self._is_ip(ip)):
				r = requests.get("http://ipinfo.io/{0}/json".format(ip))
				return r.text
			else:
				return False
		else:
			return self.get_my_ip()

class ui(Cmd):

	intro = """
	_ ___  _ _  _ ____ ____           _ ____ 
	| |__] | |\ | |___ |  |           | |  | 
	| |    | | \| |    |__|    ___    | |__| 

	 the most extensive api for ipinfo.io
	       (and another recon tool)

	commands:
		getasnofip             use help <cmd>
		getasnips              for more info
		whatsmyip
		getasn
		getip
                                         
    """

	green = '\033[92m'
	bold = '\033[1m'
	end = '\033[0m'
	ipinfo = ipinfo_io()
	prompt = green+"ipinfo> "+end

	def do_whatsmyip(self, args):
		"""
		return your ip address
		"""
		if(args == "1"):
			print(self.ipinfo.get_my_ip(1))
		else:
			print(self.ipinfo.get_my_ip())

	def do_getasnofip(self, ip):
		"""
		return an ip addresses autonomous system name
		"""		
		result = self.ipinfo.get_asn_of_ip(ip)
		if(result):
			print(result)
		else:
			print('Invalid IP')

	def do_getasn(self, asn):
		"""
		return an autonomous system's information
		"""
		result = self.ipinfo.get_asn(asn)
		if(result):
			print(json.dumps(result))
		else:
			print('Invalid ASN')

	def do_getasnips(self, asn):
		"""
		iterate through the asn's netblocks and return every ip address
		(ipv6 not supported)
		"""
		result = self.ipinfo.get_asn_ips(asn)
		if(result):
			print(json.dumps(result))
		else:
			print('Invalid ASN')

	def do_getip(self, ip):
		"""
		get information on an ip address
		"""
		result = self.ipinfo.get_ip(ip)
		if(result):
			print(result)
		else:
			print('Invalid IP')

	def do_clear(self, void):
		"""
		clear the screen
		"""
		os.system("clear")
	
	def do_cls(self, void):
		"""
		clear with cls cuz you use windows (lol)
		"""
		os.system("cls")

	def do_EOF(self, void):
		return True

	def do_exit(self, void):
		return True

if __name__ == "__main__":
	ui = ui()
	ui.cmdloop()
