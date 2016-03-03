#! /usr/bin/env python

# Standard libraries
import argparse
import os
import urllib2

# 3rd party libraries
import boto3
import boto3.session
import netaddr

# Project libraries
import deepsecurity.manager

def parse_args(str_to_parse=None):
	"""
	Parse the command line args
	"""
	description = """Deep Security uses the concept of IP Lists to make firewall rules easier
	to administer. The AWS WAF uses a similar concept of IP Sets as rule 
	conditions.

	This utility helps synchronize Deep Security IP Lists with AWS WAF
	IP Sets.
	"""
	parser = argparse.ArgumentParser(description=description)

	parser.add_argument('-d', '--ds', action='store', dest="ip_list", required=False, help='Specify an IP List within Deep Security as the source for the AWS WAF IP Set')
	parser.add_argument('-l', '--list', action='store_true', required=False, help='List the available Deep Security IP Lists and the AWS WAF IP Sets')
	parser.add_argument('-m', '--dsm', action='store', default='app.deepsecurity.trendmicro.com', required=False, help='The address of the Deep Security Manager. Defaults to Deep Security as a Service')
	parser.add_argument('--dsm-port', action='store', default='443', dest='dsm_port', required=False, help='The address of the Deep Security Manager. Defaults to Deep Security as a Service')
	parser.add_argument('-u', '--username', action='store', required=True, help='The Deep Security username to access the IP Lists with. Should only have read-only rights to IP lists and API access')
	parser.add_argument('-p', '--password', action='store', required=True, help='The password for the specified Deep Security username. Should only have read-only rights to IP lists and API access')
	parser.add_argument('-t', '--tenant', action='store', required=False, default=None, help='The name of the Deep Security tenant/account')
	parser.add_argument('--ignore-ssl-validation', action='store_true', dest='ignore_ssl_validation', required=False, help='Ignore SSL certification validation. Be careful when you use this as it disables a recommended security check. Required for Deep Security Managers using a self-signed SSL certificate')
	parser.add_argument('--dryrun', action='store_true', required=False, help='Do a dry run of the command. This will not make any changes to your AWS WAF service')
	parser.add_argument('--verbose', action='store_true', required=False, help='Enabled verbose output for the script. Useful for debugging')

	if str_to_parse:
		return parser.parse_args(str_to_parse)	
	else:
		return parser.parse_args()

class ScriptContext():
	"""
	Context for IP List to IP Set script.

	Using an object makes is easy to avoid any globals and clarifies 
	the intention of the script
	"""
	def __init__(self, args):
		self.args = args
		self.aws_credentials = None
		self.dsm = None
		self.ip_lists = []
		self.waf = None
		self.ip_sets = []

		self.aws_credentials = self._get_aws_credentials()
		self.dsm = self._connect_to_deep_security()
		self.waf = self._connect_to_aws_waf()
		self.ip_lists = self._get_available_ds_lists()

	def __del__(self): self.clean_up() # clean up on object destruction

	def _log(self, message, priority=False):
		# @TODO add actual logging :-)
		if priority or self.args.verbose:
			print message

	def clean_up(self):
		"""
		Gracefully dispose of the script's context
		"""
		if self.dsm:
			try:
				self.dsm.finish_session()
			except Exception, err: pass

	def _get_aws_credentials(self):
		"""
		Get a set of AWS credentials from a pre-configured AWS CLI installation
		"""
		credentials = None

		# check locally for an AWS CLI installation
		aws_credentials_path = [ '{}/.aws/credentials'.format(os.environ['HOME']), "{}\.aws\credentials".format(os.environ['HOME']) ]
		for path in aws_credentials_path:
			if os.path.exists(path) and not credentials:
				self._log("Reading AWS credentials from {}".format(path))
				with open(path) as fh:
					for line in fh:
						if line.startswith('aws_access_key_id'):
							credentials = { 'aws_access_key_id': line.split('=')[-1].strip() }
						elif line.startswith('aws_secret_access_key'):
							credentials['aws_secret_access_key'] = line.split('=')[-1].strip()

		return credentials

	def _connect_to_deep_security(self):
		dsm = None
		if self.args.ignore_ssl_validation:
			self._log("""***********************************************************************
* IGNORING SSL CERTIFICATE VALIDATION
* ===================================
* You have requested to ignore SSL certificate validation. This is a less secure method 
* of connecting to a Deep Security Manager (DSM). Please ensure that you have other 
* mitigations and security controls in place (like restricting IP space that can access 
* the DSM, implementing least privilege for the Deep Security user/role accessing the 
* API, etc).
*
* During script execution, you'll see a number of "InsecureRequestWarning" messages. 
* These are to be expected when operating without validation. 
***********************************************************************""", priority=True)
		try:
			dsm = deepsecurity.manager.Manager(dsm_hostname=self.args.dsm, dsm_port=self.args.dsm_port, username=self.args.username, password=self.args.password, tenant=self.args.tenant, ignore_ssl_validation=self.args.ignore_ssl_validation) 
			self._log("Connected to the Deep Security Manager at {}".format(self.args.dsm))
		except Exception, err: pass # @TODO handle this exception gracefully

		if not dsm.session_id_rest and not dsm.session_id_soap:
			self._log("Unable to connect to the Deep Security Manager. Please check your settings")
			if not self.args.ignore_ssl_validation:
				self._log("You did not ask to ignore SSL certification validation. This is a common error when connect to a Deep Security Manager that was installed via software or the AWS Marketplace. Please set the flag (--ignore-ssl-validation), check your other settings, and try again")

		return dsm

	def _connect_to_aws_waf(self):
		waf = None
		try:
			aws = boto3.session.Session(aws_access_key_id=self.aws_credentials['aws_access_key_id'], aws_secret_access_key=self.aws_credentials['aws_secret_access_key'])
			waf = aws.client('waf') 
			self._log("Connected to AWS WAF")
		except Exception, err: 
			# @TODO handle this exception gracefully
			try:
				waf = boto3.client('waf')
				self._log("Connected to AWS WAF")
			except Exception, err: pass # @TODO handle this exception gracefully	

		return waf

	def _get_available_ds_lists(self):
		"""
		Query Deep Security for any existing IP Lists
		"""
		ip_lists = None

		if self.dsm:
			self.dsm.get_ip_lists()
			ip_lists = self.dsm.ip_lists
			self._log("Cached the available IP Lists from Deep Security")

		return ip_lists

	def get_ds_list(self, list_id):
		"""
		Get the specified IP List from the cached results
		"""
		ip_list = None

		for key in self.ip_lists.keys():
			if '{}'.format(list_id.strip()) == str(key):
				ip_list = self.ip_lists[key]
				self._log("Found Deep Security IP list [{}]".format(ip_list))
				break

		return ip_list

	def get_available_aws_sets(self):
		"""
		Get a list of the available IP Sets in AWS WAF
		"""
		ip_sets = []
		if self.waf:
			response = self.waf.list_ip_sets(Limit=100)
			if response and response.has_key('IPSets'):
				for ip_set in response['IPSets']:
					ip_sets.append(ip_set)

		self.ip_sets = ip_sets

		return ip_sets

	def _get_aws_waf_change_token(self):
		response = self.waf.get_change_token()
		change_token = None
		if response and response.has_key('ChangeToken'):
			change_token = response['ChangeToken']
			self._log("New AWS WAF change token [{}]".format(change_token))

		return change_token

	def _expand_cidr(self, cidr):
		# AWS WAF IP Sets only accept octets of ['8','16','24','32']
		# find the next largest one to expand the specified CIDR
		# to the smallest possible set
		blocks = []

		# yes, you can figure the strata out algorithmically but this
		# is a little more readable and will definitely help with long
		# term maintenance which is way more important!
		strata = { # defines the CIDR octet blocks
			32: { 'type': 32, 'times': 1, 'size': 1 },
			31: { 'type': 32, 'times': 2, 'size': 1 },
			30: { 'type': 32, 'times': 4, 'size': 1 },
			29: { 'type': 32, 'times': 8, 'size': 1 },
			28: { 'type': 32, 'times': 16, 'size': 1 },
			27: { 'type': 32, 'times': 32, 'size': 1 },
			26: { 'type': 32, 'times': 64, 'size': 1 },
			25: { 'type': 32, 'times': 128, 'size': 1 },
			24: { 'type': 24, 'times': 1, 'size': 256 },
			23: { 'type': 24, 'times': 2, 'size': 256 },
			22: { 'type': 24, 'times': 4, 'size': 256 },
			21: { 'type': 24, 'times': 8, 'size': 256 },
			20: { 'type': 24, 'times': 16, 'size': 256 },
			19: { 'type': 24, 'times': 32, 'size': 256 },
			18: { 'type': 24, 'times': 64, 'size': 256 },
			17: { 'type': 24, 'times': 128, 'size': 256 },
			16: { 'type': 16, 'times': 1, 'size': 65536 },
			15: { 'type': 16, 'times': 2, 'size': 65536 },
			14: { 'type': 16, 'times': 4, 'size': 65536 },
			13: { 'type': 16, 'times': 8, 'size': 65536 },
			12: { 'type': 16, 'times': 16, 'size': 65536 },
			11: { 'type': 16, 'times': 32, 'size': 65536 },
			10: { 'type': 16, 'times': 64, 'size': 65536 },
			9: { 'type': 16, 'times': 128, 'size': 65536 },
			8: { 'type': 8, 'times': 1, 'size': 16777216 },
			7: { 'type': 8, 'times': 2, 'size': 16777216 },
			6: { 'type': 8, 'times': 4, 'size': 16777216 },
			5: { 'type': 8, 'times': 8, 'size': 16777216 },
			4: { 'type': 8, 'times': 16, 'size': 16777216 },
			3: { 'type': 8, 'times': 32, 'size': 16777216 },
			2: { 'type': 8, 'times': 64, 'size': 16777216 },
			1: { 'type': 8, 'times': 128, 'size': 16777216 },
		}

		current_strata = int(cidr.__str__().split('/')[-1])
		for i in range(strata[current_strata]['times']):
			if i == 0:
				current_cidr = netaddr.IPNetwork('{}/{}'.format(cidr[0], strata[current_strata]['type']))
			else:
				index = i * strata[current_strata]['size']
				current_cidr = netaddr.IPNetwork('{}/{}'.format(cidr[index], strata[current_strata]['type']))
	
			blocks.append(current_cidr)

		self._log("Expanded CIDR block {} to {} IP Set compatible blocks".format(cidr, len(blocks)))

		return blocks

	def _parse_ds_addresses(self, ds_list):
		# Accepted DS formats
		# X.X.X.X/1-32	Example: 192.168.2.0/24
		# X.X.X.X/Y.Y.Y.Y	Example: 192.168.2.0/255.255.255.0
		# X.X.X.X	Example: 192.168.2.33
		# IpV6 Mask	Example: 2001:0DB8::CD30:0:0:0:0/60
		# X.X.X.X-Y.Y.Y.Y	Example: 192.168.0.2 - 192.168.0.125
		# IPv6-IPv6	Example: FF01::101 - FF01::102
		# IP or Range #Comment	Example: 255.255.255.255 #Broadcast IP
		addresses = []
		for address in ds_list.addresses:
			if "#" in address: address = address.split('#').strip() # remove any comments
			if '-' in address:
				try:
					a1, a2 = address.split('-')
					# what's the range between a1 and a2?
					rng = netaddr.IPRange(a1, a2)
					for addr in rng: addresses.append(netaddr.IPNetwork(addr))
				except Exception, err: pass
			else:
				net = netaddr.IPNetwork(address)
				if '{}'.format(net.cidr).split('/')[-1] in ['8','16','24','32']:
					addresses.append(netaddr.IPNetwork(net))
				else:
					for addr in net: addresses.append(netaddr.IPNetwork(addr)) 

		total_set = netaddr.IPSet(addresses)
		total_set.compact()

		cidrs = total_set.iter_cidrs()
		waf_compatible = []
		for cidr in cidrs:
			if '{}'.format(cidr).split('/')[-1] in ['8','16','24','32']:
				waf_compatible.append(cidr)
			else:
				waf_compatible += self._expand_cidr(cidr)

		self._log("Converted {} IP List entries to {} IP Set entries".format(len(ds_list.addresses), len(waf_compatible)), priority=True)
		return waf_compatible

	def _convert_ds_addresses_to_waf(self, ds_list, convert='ignore'):
		"""
		convert = One of ['ignore', 'expand', 'upscale']
		"""
		# AWS WAF IP Sets only accept CIDR notation with a closing octet of /8 /16 /24 or /32
		# We need to ensure that the specified Deep Security IP List will convert to an IP Set
		addresses = self._parse_ds_addresses(ds_list)

		updates = []
		for cidr_network in addresses:
			updates.append(
					{
						'Action': 'INSERT',
						'IPSetDescriptor': {
							'Type': 'IPV{}'.format(cidr_network.version),
							'Value': cidr_network.cidr.__str__(),
							}
					}
				)

		return updates

	def create_ip_set(self, ds_list):
		"""
		Create an AWS WAF IP Set based on the specified Deep Security IP List
		"""
		if self.waf:
			# is there an existing IP Set?
			current_ip_set = None
			if not self.ip_sets: self.get_available_aws_sets()
			for ip_set in self.ip_sets:
				if ip_set.has_key('Name') and ip_set['Name'] == ds_list.name:
					current_ip_set = ip_set['IPSetId']
					break

			response = self.waf.get_change_token()
			change_token = self._get_aws_waf_change_token()

			if change_token:
				list_created = False
				if not current_ip_set:
					if not self.args.dryrun:
						self._log("Requesting the creation of [{}]".format(ds_list.name))
						response = self.waf.create_ip_set(Name=ds_list.name, ChangeToken=change_token)
						if response:
							self.ip_sets.append(response['IPSet'])
							list_created = True
							current_ip_set = response['IPSet']['IPSetId']
							change_token = self._get_aws_waf_change_token()
					else:
						self._log("Will request the creation of [{}]".format(ds_list.name), priority=True)

				if current_ip_set and change_token:
					updates = self._convert_ds_addresses_to_waf(ds_list)
					if len(updates) > 1000:
						self._log("Requested IP List converts to more then the 1000 entry limit for an IP Set. Please split the IP List within Deep Security before syncing with AWS WAF", priority=True)
					else:
						if not self.args.dryrun:
							response = self.waf.update_ip_set(IPSetId=current_ip_set, ChangeToken=change_token, Updates=updates)
							if response and response.has_key('ChangeToken'):
								self._log('Change [{}] requested'.format(response['ChangeToken']))
						else:
							self._log("Will request the addition of {} entries in IP Set {}".format(len(updates), current_ip_set), priority=True)

					if not self.args.dryrun:
						msg_verb = "Created" if list_created else "Updated"
						self._log("{} IP Set [{}] with ID [{}]".format(msg_verb, ds_list.name, current_ip_set), priority=True)
					else:
						msg_verb = "create" if list_created else "update"
						self._log("Will {} IP Set [{}] with ID [{}]".format(msg_verb, ds_list.name, current_ip_set), priority=True)

	def print_lists(self):
		"""
		Pretty print the IP lists from Deep Security and
		the AWS WAF IP Sets
		"""
		print "\nAvailable Deep Security IP Lists"
		print "================================"
		if self.ip_lists and len(self.ip_lists) > 0:
			for ds_list_id, ds_list in self.ip_lists.items():
				print "{}\t{}".format(ds_list_id, ds_list.name)
		else:
			print "---\t No IP lists available"


		print "\nAvailable AWS WAF IP Sets"
		print "========================="
		if self.ip_sets and len(self.ip_sets) > 0:
			for waf_set in self.ip_sets:
				print "{}\t{}".format(waf_set['IPSetId'], waf_set['Name'])
		else:
			print "---\t No AWS WAF WACLs available"

def main():
	"""
	Run the script from the command line
	"""
	context = ScriptContext(parse_args())

	if context.args.list:
		# List the available Deep Security IP Lists and AWS WAF IP Sets
		context.get_available_aws_sets()
		context.print_lists()

	elif context.args.ip_list:
		if context.args.dryrun:
			context._log("***********************************************************************", priority=True)
			context._log("* DRY RUN ENABLED. NO CHANGES WILL BE MADE", priority=True)
			context._log("***********************************************************************", priority=True)
		# get the specified Deep Security IP Lists (already cached)
		ip_list = context.get_ds_list(context.args.ip_list)
		# create the IP Set
		if ip_list:
			context.create_ip_set(ip_list)

	context.clean_up()

if __name__ == '__main__': main()