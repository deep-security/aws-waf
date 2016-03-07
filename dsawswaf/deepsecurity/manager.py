# Standard libraries
import datetime
#import dateutil.parser
import json
import inspect
import logging
import os
import urllib
import xml.etree.ElementTree as ET

# 3rd party libraries
import requests
import suds

# Project libraries
import application_type
import cloud_account
import computer
import computer_group
import firewall_rule
import integrity_monitoring_rule
import intrusion_prevention_rule
import ip_list
import log_inspection_rule
import policy
import soap_https_handler

class Manager(object):
	"""
	Class representing the Deep Security Manager and all of it's 
	functionality. Well, at least the functionality available via the 
	SOAP and REST APIs
	"""
	def __init__(self, username=None, password=None, tenant='Primary', dsm_hostname=None, dsm_port=443, start_session=True, ignore_ssl_validation=False, debug=False):
		"""
		Create a new reference to a Deep Security Manager

		username = 	str value of the username to authenticate to Deep Security with
		password = 	The password  for the specified userName
		tenant = 		In a multi-tenant deployment (like Deep Security as a Service) this is the tenant/account name. 
								For non-multi tenant accounts this can be left blank or set to "primary"
		dsm_hostname = The hostname of the Deep Security Manager to access, defaults to Deep Security as a Service
		dsm_port = The port of the Deep Security Manager to access, defaults to Deep Security as a Service
		start_session = Whether or not to automatically start a session with the specified Deep Security Manager
		"""
		self.version = '9.6'
		self._hostname = 'app.deepsecurity.trendmicro.com' if not dsm_hostname else dsm_hostname # default to Deep Security as a Service
		self._port = dsm_port # on-premise defaults to 4119
		self.rest_api_path = 'rest'
		self.soap_api_wsdl = 'webservice/Manager?WSDL'
		self.session_id_rest = None
		self.session_id_soap = None
		self.soap_client = None
		self.ignore_ssl_validation = ignore_ssl_validation

		# Deep Security data
		self.computer_groups = {}
		self.policies = {}
		self.computers = {}
		self.computer_details = {}
		self.cloud_accounts = {}
		self.ip_lists = {}
		self.application_types = {}
		self.rules = {
			'intrusion_prevention': {},
			'firewall': {}, 
			'web_reputation': {},
			'integrity_monitoring': {},
			'log_inspection': {},
		}

		# Setup functions
		self._debug = debug
		self.logger = self._setup_logging()
		self._set_url()

		# Try to start a session if possible
		if username and password and start_session:
			self.log("Attempting to start a session")
			self.start_session(username=username, password=password, tenant=tenant)

	def __del__(self):
		"""
		Try to gracefully clean up the session
		"""
		try:
			self.finish_session()
		except Exception, err: pass

	def __str__(self):
		"""
		Return a better string representation
		"""
		return "Manager <{}:{}>".format(self._hostname, self._port)

	# *****************************************************************
	# Properties
	# *****************************************************************
	# Any change to .hostname requires the API endpoints be recalculated
	@property
	def hostname(self): return self._hostname

	@hostname.setter
	def hostname(self, val):
		"""
		Ensure that any change to .hostname triggers a recalculation of the
		API endpoints
		"""
		self._hostname = val
		self._set_url()

	# Ditto for any change to .port
	@property
	def port(self): return self._port

	@port.setter
	def port(self, val):
		"""
		Ensure that any change to .port triggers a recalculation of the
		API endpoints
		"""
		self._port = val
		self._set_url()

	# Any change to debug requires that logging be reset
	@property
	def debug(self): return self._debug
	
	@debug.setter
	def debug(self, val):
		"""
		Reset the logging configuration on change
		"""
		self._setup_logging()

	# *****************************************************************
	# 'Private' methods
	# *****************************************************************
	def _setup_logging(self):
		"""
		Setup the overall logging environment
		"""

		# Based on tips from http://www.blog.pythonlibrary.org/2012/08/02/python-101-an-intro-to-logging/
		logging.basicConfig(level=logging.ERROR)
		if self._debug:
			logging.basicConfig(level=logging.DEBUG)

		# turn down suds logging
		logging.getLogger('suds.client').setLevel(logging.ERROR)
		if self._debug:
			logging.getLogger('suds.client').setLevel(logging.DEBUG)

		# setup module logging
		logger = logging.getLogger("DeepSecurity.API")
		logger.setLevel(logging.WARNING)
		if self._debug:
			logger.setLevel(logging.DEBUG)

		formatter = logging.Formatter('[%(asctime)s]\t%(message)s', '%Y-%m-%d %H:%M:%S')
		stream_handler = logging.StreamHandler()
		stream_handler.setFormatter(formatter)
		logger.addHandler(stream_handler)

		return logger

	def _get_call_structure(self, api='soap'):
		"""
		Return the default call structure.
		call = {
			'api': 'rest' or 'soap',
			'method': 'url_fragment' or 'name of soap method',
			'auth': True auth is required, False it isn't,
			'data': dict to post or use as kwargs for soap method,
			'query': dict to use as a query string for rest methods,
		}
		"""
		return {
			'api': api, # 'rest' also valid
			'auth': True,
			'method': None,
			'query': None,
			'data': None,
			}

	def _get_soap_client(self, force_load_from_url=False):
		"""
		Create a suds SOAP client based on the DSM WSDL
		"""
		soap_client = None

		try:
			if self.ignore_ssl_validation:
				self.log("Ignoring SSL validation for SOAP API access")
				soap_client = suds.client.Client(self.base_url_for_soap, transport=soap_https_handler.HTTPSIgnoreValidation())
			else:
				soap_client = suds.client.Client(self.base_url_for_soap)
		except Exception, soap_err:
			self.log("Could not create a SOAP client. Threw exception: %s" % soap_err)
			soap_client = None

		return soap_client

	def _set_url(self):
		"""
		Set the correct API endpoints given the current hostname:port
		"""
		for api, end_fragment in {
							'base_url_for_rest': self.rest_api_path,
							'base_url_for_soap': self.soap_api_wsdl,
							}.items():
			url = 'https://{}:{}/{}'.format(self.hostname, self.port, end_fragment)
			setattr(self, api, url)

		# Update the SOAP client just in case we're dealing with a new WSDL
		self.soap_client = self._get_soap_client()

	def _make_a_rest_call(self, call):
		"""
		Make a call to the Deep Security REST API and return the result.
		Returns 'None' and logs if there were any issues 
		"""
		result = None

		headers = {
			'Accept': 'application/json',
			'Content-Type': 'application/json',
			}

		# authentication calls don't accept the Accept header
		if call['method'].startswith('authentication'): del(headers['Accept'])

		# Make sure we can make a REST call
		if not self.base_url_for_rest:
			self._set_url()
			if not self.base_url_for_rest: return result

		# Get the full URL of the REST API call
		full_url = '%s/%s' % (self.base_url_for_rest, call['method'].lstrip('/'))

		# Prep the query string
		if call.has_key('query') and call['query']:
			# get with query string
			qs = {}
			for k, v in call['query'].items(): # strip out null entries
				if v: qs[k] = v
			full_url += '?%s' % urllib.urlencode(qs)

		# Make the call
		if call.has_key('query') and call['query'] and not call.has_key('data'):
			# GET
			try:
				result = requests.get(full_url, headers=headers, verify=not self.ignore_ssl_validation)
			except Exception, get_err:
				self.log("Failed to get REST call [%s] with query string. Threw exception: /%s" % (call['method'].lstrip('/'), post_err))					
		elif call.has_key('data') and call['data']:
			# POST
			try:
				result = requests.post(full_url, data=json.dumps(call['data']), headers=headers, verify=not self.ignore_ssl_validation)
			except Exception, post_err:
				self.log("Failed to post REST call [%s]. Threw exception: /%s" % (call['method'].lstrip('/'), post_err))	
		else:
			# default to GET
			try:
				result = requests.get(full_url, headers=headers)
			except Exception, get_err:
				self.log("Failed to get REST call [%s]. Threw exception: /%s" % (call['method'].lstrip('/'), post_err))	

		return result

	def _make_a_soap_call(self, call):
		"""
		Make a call to the Deep Security SOAP API and return the result.
		Returns 'None' and logs to stderr if there were any issues 
		"""
		# to debug print self.soap_client.last_received().str()
		# to debug print self.soap_client.last_sent().str()
		result = None

		# Make sure we can make a SOAP call
		if not self.base_url_for_soap:
			self._set_url()
			if not self.base_url_for_soap: return result

		data = {}
		if call.has_key('data') and type(call['data']) == type({}): data = call['data']
		try:
			result = getattr(self.soap_client.service, '%s' % call['method'])(**data)
		except Exception, soap_err:
			self.log("Failed to make SOAP call [%s]. Threw exception: %s" % (call['method'], soap_err))
			result = None

		return result

	def _make_call(self, call):
		"""
		Make an API call to either the SOAP or REST API

		Default 'call' structure:
			call = {
				'api': 'rest' or 'soap',
				'method': 'url_fragment' or 'name of soap method',
				'auth': True auth is required, False it isn't,
				'data': dict to post or use as kwargs for soap method,
				'query': dict to use as a query string for rest methods,
			}
		"""
		result = None

		call_details = {}
		for k, v in call.items(): 
			if v: call_details[k] = v

		# If the call requires authentication, make sure we have a current session
		if call_details.has_key('auth') and call_details['auth']:
			if (call['api'] == 'soap' and not self.session_id_soap) or (call['api'] == 'rest' and not self.session_id_rest): 
				self.log("Could not make %s API call. This call requires a valid session" % call_details['api'].upper())
				return result

		if call_details['api'] in ['rest', 'soap']:
			result = getattr(self, '_make_a_%s_call' % call_details['api'])(call_details)

		return result

	def _search_in_dict(self, search_for, in_dict, by_attribute=None):
		"""
		Search through a dict collection to find a matching object
		"""
		search_for = search_for.lower()

		d = None
		try:
			if in_dict in dir(self):
				d = getattr(self, in_dict)
		except Exception, err:
			self.log("Could not find [{}] to search for [{}]".format(in_dict, search_for))

		results = []
		if d:
			for k, v in d.items():
				if by_attribute:
					if by_attribute in dir(v):
						comparison = "{}".format(getattr(v, by_attribute)).lower()
						if search_for in comparison:
							results.append(k)
				else:
					for attr_name in [
						'name',
						'hostname',
						'display_name',
						'description',
						]:
						if attr_name in dir(v):
							comparison = "{}".format(getattr(v, attr_name)).lower()
							if search_for in comparison:
								results.append(k)
								break # out of the inner loop

		return results

	# *****************************************************************
	# Public methods - API session management
	# *****************************************************************
	def log(self, message, err=None, level="info"):
		"""
		Log the specified message
		"""
		if err:
			self.logger.error("{}\nThrew exception:\n\t{}".format(message, err))
		else:
			self.logger.info(message)

	def start_session(self, username=None, password=None, tenant=None, force_new_session=False):
		"""
		Authenticate to the REST and SOAP APIs and start a new session for each
		"""
		if force_new_session: self.finish_session()

		# We need to make different calls for tenants and the primary
		soap_call = None
		rest_call = None
		if not tenant or tenant.lower() == "primary":
			soap_call = self._get_call_structure()
			soap_call['auth'] = False
			soap_call['method'] = 'authenticate'
			soap_call['data'] = {
					'username': username,
					'password': password,
				}

			rest_call = self._get_call_structure(api='rest')
			rest_call['auth'] = False
			rest_call['method'] = 'authentication/login/primary'
			rest_call['data'] = { 'dsCredentials':
					{
				   	'userName': username,
				  	'password': password,
					}
				}
		else:
			soap_call = self._get_call_structure()
			soap_call['auth'] = False
			soap_call['method'] = 'authenticateTenant'
			soap_call['data'] = {
					'tenantName': tenant,
					'username': username,
					'password': password,
				}

			rest_call = self._get_call_structure(api='rest')
			rest_call['auth'] = False
			rest_call['method'] = 'authentication/login'
			rest_call['data'] = {'dsCredentials':
					{
					'tenantName': tenant,
				   	'userName': username,
				  	'password': password,
					}
				}

		# Do we have an existing SOAP session?
		if not self.session_id_soap or force_new_session:
			if soap_call: self.session_id_soap = self._make_call(soap_call)

			if self.session_id_soap:
				self.log("Authenticated successfully, starting SOAP session [%s]" % self.session_id_soap)
			else:
				self.log("Could not start SOAP session")
		elif self.session_id_soap:
			self.log("Continuing with SOAP session [%s]" % self.session_id_soap)

		# Do we have an existing REST session?
		if not self.session_id_rest or force_new_session:
			if rest_call: 
				response = self._make_call(rest_call)
				if response:
					self.session_id_rest = response.text

			if self.session_id_rest:
				self.log("Authenticated successfully, starting REST session [%s]" % self.session_id_rest)
			else:
				self.log("Could not start REST session")
		elif self.session_id_rest:
			self.log("Continuing with REST session [%s]" % self.session_id_rest)

		return (self.session_id_rest, self.session_id_soap)

	def finish_session(self):
		"""
		Terminate an existing session
		"""
		if self.session_id_soap and self.soap_client:
			soap_call = {
					'api': 'soap',
					'method': 'endSession',
					'data': {
						'sID': self.session_id_soap,
					},
					'auth': True,
				}
			rest_call = {
					'api': 'rest',
					'method': 'authentication/logout',
					'query': {
						'sID': self.session_id_rest,
					},
					'auth': False,
				}

			result = self._make_call(soap_call)
			result = self._make_call(rest_call)
			self.log("Terminated sessions [%s] & [%s]" % (self.session_id_soap, self.session_id_rest))
	
		old_session_id_soap = self.session_id_soap
		old_session_id_rest = self.session_id_rest
		self.session_id_soap = None
		self.session_id_rest = None

		return ('-{}'.format(old_session_id_rest), '-{}'.format(old_session_id_soap))

	def close(self): self.finish_session()

	# *****************************************************************
	# Public methods - manager basics
	# *****************************************************************
	def find_computers(self, with_name, by_attribute=None): return self._search_in_dict(with_name, 'computers', by_attribute=by_attribute)
	def find_policies(self, with_name, by_attribute=None): return self._search_in_dict(with_name, 'policies', by_attribute=by_attribute)
	def find_computer_groupss(self, with_name, by_attribute=None): return self._search_in_dict(with_name, 'computer_groups', by_attribute=by_attribute)
	def find_cloud_accounts(self, with_name, by_attribute=None): return self._search_in_dict(with_name, 'cloud_accounts', by_attribute=by_attribute)

	def is_up(self, full_check=False):
		"""
		Ping the DSM to see if it's up and responding to requests. Use the
		full_check argument to specify whether or not to ping the DSM or
		to use the API to check the full technology stack
		"""
		if full_check:
			# Call the REST API's ping method for the manager which
			# checks the full technology stack for DSM
			call = {
				'api': 'rest',
				'method': 'status/manager/ping',
				'auth': False,
			}
			results = self._make_call(call)
			if results.status_code == requests.codes.ok:
				return True
			else:
				return False
		else:
			# just ping the REST API's front door
			full_url = self.base_url_for_rest
			try:
				results = requests.get(full_url, headers={"content-type":"application/json"})
				if results.status_code == 200 or results.status_code == 404:
					return True
				else:
					return False
			except Exception, get_err:
				self.log.error("Could not ping {}. Threw exception: {}".format(full_url,  get_err))
				return False

	def get_all(self):
		"""
		Get all of the information from Deep Security:
		   - computer groups
		   - computers
		   - policies
		   - cloud accounts
		   - ip lists
		"""
		self.get_computer_groups()
		self.get_computers_with_details()
		self.get_policies()
		self.get_cloud_accounts()
		self.get_ip_lists()

	def get_computer_groups(self):
		"""
		Get a list of the Computer Groups added to Deep Security
		"""
		call = {
			'api': 'soap',
			'method': 'hostGroupRetrieveAll',
			'data': {
				'sID': self.session_id_soap,
			},
			'auth': True,
		}
		
		results = self._make_call(call)
		if results:
			if not self.computer_groups: self.computer_groups = {}
			for group in results:
				self.computer_groups[group['ID']] = computer_group.ComputerGroup(group, manager=self)

	def get_policies(self):
		"""
		Get a list of the Policies configured in Deep Security
		"""
		call = {
			'api': 'soap',
			'method': 'securityProfileRetrieveAll',
			'data': {
				'sID': self.session_id_soap,
			},
			'auth': True,
		}
		
		results = self._make_call(call)
		if results:
			if not self.policies: self.policies = {}
			for result in results:
				self.policies[result['ID']] = policy.Policy(result, manager=self)

	def get_computers(self):
		"""
		Get a list of the Computers managed by Deep Security
		"""
		call = {
			'api': 'soap',
			'method': 'hostRetrieveAll',
			'data': {
				'sID': self.session_id_soap,
			},
			'auth': True,
		}
		
		results = self._make_call(call)
		if results:
			if not self.computers: self.computers = {}
			for result in results:
				self.computers[result['ID']] = computer.Computer(result, manager=self)

	def get_computers_with_details(self, detail_level='HIGH'):
		"""
		Get a list of all the Computers managed by Deep Security

		Acceptable values for detail_level are:
		- HIGH
		- MEDIUM
		- LOW
		"""
		host_filter_type = self.soap_client.factory.create("EnumHostFilterType")
		host_details = self.soap_client.factory.create("EnumHostDetailLevel")
		host_filter_transport = self.soap_client.factory.create("HostFilterTransport")
		host_filter_transport['type'] = host_filter_type['ALL_HOSTS']

		# HostFilterType structure
		# (EnumHostFilterType){
		#   ALL_HOSTS = "ALL_HOSTS"
		#   HOSTS_IN_GROUP = "HOSTS_IN_GROUP"
		#   HOSTS_USING_SECURITY_PROFILE = "HOSTS_USING_SECURITY_PROFILE"
		#   HOSTS_IN_GROUP_AND_ALL_SUBGROUPS = "HOSTS_IN_GROUP_AND_ALL_SUBGROUPS"
		#   SPECIFIC_HOST = "SPECIFIC_HOST"
		#   MY_HOSTS = "MY_HOSTS"
		# }
		call = {
			'api': 'soap',
			'method': 'hostDetailRetrieve',
			'data': {
				'sID': self.session_id_soap,
				'hostFilter': host_filter_transport,
				'hostDetailLevel': host_details[detail_level],
			},
			'auth': True,
		}
		
		results = self._make_call(call)
		if results:
			if not self.computers: self.computers = {}
			for result in results:
				self.computers[result['ID']] = computer.Computer(result, manager=self)

	def get_computer_details(self, computer_hostname=None):
		"""
		Get details on a specific computer managed by Deep Security
		"""
		host_details = self.soap_client.factory.create("EnumHostDetailLevel")
		call = {
			'api': 'soap',
			'method': 'hostDetailRetrieveByName',
			'data': {
				'sID': self.session_id_soap,
				'hostname': computer_hostname,
				'hostDetailLevel': host_details['HIGH'],
			},
			'auth': True,
		}
		
		result = self._make_call(call)
		if result:
			if not self.computer_details: self.computer_details = {}

			for host_detail in result:
				self.computer_details[host_detail['ID']] = computer.Computer(host_details=host_detail, manager=self)

	def get_cloud_accounts(self):
		"""
		Get a list of the currently configured cloud accounts
		"""
		call = {
					'api': 'rest',
					'method': 'cloudaccounts',
					'query': {
						'sID': self.session_id_rest,
					},
					'auth': True,
				}
		
		results = self._make_call(call)
		if results and results.ok:
			results_doc = results.json()
			if results_doc.has_key('cloudAccountListing'):
				self.cloud_accounts = results_doc['cloudAccountListing']

		return self.cloud_accounts

	def get_aws_accounts(self): return self.get_cloud_accounts()

	def add_aws_account(self, name, access_key, secret_key, region="all"):
		"""
		Add a cloud account to synchronize inventory with a cloud service provider
		"""
		regions = {
			'us-east-1': 'amazon.cloud.region.key.1',
			'us-west-1': 'amazon.cloud.region.key.2',
			'us-west-2': 'amazon.cloud.region.key.3',
			'eu-west-1': 'amazon.cloud.region.key.4',
			'ap-southeast-1': 'amazon.cloud.region.key.5',
			'ap-northeast-1': 'amazon.cloud.region.key.6',
			'sa-east-1': 'amazon.cloud.region.key.7',
		}

		call = {
			'api': 'rest',
			'method': 'cloudaccounts',
			'data': {
				'createCloudAccountRequest': {
					'sessionId': self.session_id_rest,
					'cloudAccountElement': {
						'accessKey': access_key,
						'secretKey': secret_key,
						'cloudType': 'AMAZON',
						'name': name,
						'cloudRegion': regions[region] if not region == "all" else ""
					}
				}
				
				},
			'auth': True,
		}

		results_by_region = {}

		if region == "all":
			for region_name, region_id in regions.items():
				call['data']['createCloudAccountRequest']['cloudAccountElement']['name'] = '{} / {}'.format(name, region_name)
				call['data']['createCloudAccountRequest']['cloudAccountElement']['cloudRegion'] = region_id
				results = self._make_call(call)
				if "Cloud Account Region/Partition already present" in results.text:
					results_by_region[region_name] = False
				elif results.ok:
					results_by_region[region_name] = True
				else:
					results_by_region[region_name] = results
		else:
			results = self._make_call(call)

			if "Cloud Account Region/Partition already present" in results.text:
				results_by_region[region] = False
			elif results.ok:
				results_by_region[region] = True
			else:
				results_by_region[region] = results

		return results_by_region

	def get_ip_lists(self):
		"""
		Get a list of all of the current IP lists in Deep Security
		"""
		call = {
			'api': 'soap',
			'method': 'IPListRetrieveAll',
			'data': {
				'sID': self.session_id_soap,
			},
			'auth': True,
		}
		result = self._make_call(call)
		if result:
			for obj in result:
				self.ip_lists[obj['ID']] = ip_list.IpList(ip_list_details=obj, manager=self)

	def request_events_from_computer(self, host_id):
		"""
		Ask the computer to send the latest events it's seen to the DSM
		"""
		call = {
			'api': 'soap',
			'method': 'hostGetEventsNow',
			'data': {
				'sID': self.session_id_soap,
				'hostID': host_id,
			},
			'auth': True,
		}
		result = self._make_call(call)
		# None is returned if the call worked so we have no way of checking
		# if this worked or didn't

	def clear_warnings_and_errors_from_computer(self, host_ids):
		"""
		Clear any warnings or errors currently showing on the specified
		computers
		"""
		# Make sure we have a list for the host_ids
		if not type(host_ids) == type([]): host_ids = [ host_ids ]

		call = {
			'api': 'soap',
			'method': 'hostClearWarningsErrors',
			'data': {
				'sID': self.session_id_soap,
				'hostIDs': host_ids,
			},
			'auth': True,
		}
		result = self._make_call(call)
		# None is returned if the call worked so we have no way of checking
		# if this worked or didn't

	def scan_computers_for_malware(self, host_ids):
		"""
		Request a malware scan be run immediately on the specified
		computers
		"""
		# Make sure we have a list for the host_ids
		if not type(host_ids) == type([]): host_ids = [ host_ids ]

		call = {
			'api': 'soap',
			'method': 'hostAntiMalwareScan',
			'data': {
				'sID': self.session_id_soap,
				'hostIDs': host_ids,
			},
			'auth': True,
		}
		result = self._make_call(call)
		# None is returned if the call worked so we have no way of checking
		# if this worked or didn't

	def scan_computers_for_integrity(self, host_ids):
		"""
		Request an integrity scan be run immediately on the specified
		computers
		"""
		# Make sure we have a list for the host_ids
		if not type(host_ids) == type([]): host_ids = [ host_ids ]

		call = self._get_call_structure()
		call['method'] = 'hostIntegrityScan'
		call['data'] = {
							'sID': self.session_id_soap,
							'hostIDs': host_ids,
						}
		result = self._make_call(call)
		# None is returned if the call worked so we have no way of checking
		# if this worked or didn't

	def scan_computers_for_recommendations(self, host_ids):
		"""
		Request a recommendation scan be run immediately on the specified
		computers
		"""
		# Make sure we have a list for the host_ids
		if not type(host_ids) == type([]): host_ids = [ host_ids ]

		call = self._get_call_structure()
		call['method'] = 'hostRecommendationScan'
		call['data'] = {
							'sID': self.session_id_soap,
							'hostIDs': host_ids,
						}
		result = self._make_call(call)
		# None is returned if the call worked so we have no way of checking
		# if this worked or didn't

	def assign_policy_to_computers(self, policy_id, host_ids):
		"""
		Assign the specified security policy to the specified computers
		"""
		# Make sure we have a list for the host_ids
		if not type(host_ids) == type([]): host_ids = [ host_ids ]

		call = self._get_call_structure()
		call['method'] = 'securityProfileAssignToHost'
		call['data'] = {
							'securityProfileID': policy_id,
							'sID': self.session_id_soap,
							'hostIDs': host_ids,
						}
		result = self._make_call(call)
		# None is returned if the call worked so we have no way of checking
		# if this worked or didn't
		
	def get_computer_protection_information(self, tenant=None, from_timestamp=None, to_timestamp=None):
		"""
		Request the number of protection hours used by the specified tenant.

		If tenant_name == None, all tenants are returned (if session has sufficient rights)
		If from_timestamp == None, API defaults to 1 hour from request time
		If to_timestamp == None, API defaults to request time

		Returns a dict of 
		{
			'computer_id_key': {
					'host_id_1': str,
					'host_id_2': str,
					'host_id_3': str,
			},
			'tenant_name': {
				'computer_id': {
					'computer_id': str,
					'computer_id_1': str,
					'computer_id_2': str,
					'computer_id_3': str,
					'protection_start_date': datetime.datetime,
					'protection_stop_date': datetime.datetime,
					'total_seconds_protected': number,
					'total_protection_time': datetime.timedelta,
					'tenant_id': str,
					'tenant_name': str,
				}
			}
		}
		"""
		call = self._get_call_structure(api='rest')
		call['method'] = 'monitoring/usages/hosts/protection'
		call['query'] = {
							'sID': self.session_id_rest,
							'tenantName': tenant,
							'from': from_timestamp,
							'to': to_timestamp,
						}
		result = self._make_call(call)
		if not result: tenants = { 'computer_id_key': {} } 
		data = self._parse_rest_response(result)

		# 0--3 hostID_Type elements create an ID for the computers
		# 	hostID1Type
		# 	hostID2Type
		# 	hostID3Type
		#
		# 0--? TenantHostProtection elements
		tenants = { 'computer_id_key': {} }

		i = 0
		for node in data[0:3]: # only check the first few nodes for speed
			key = 'host_id'
			if i > 0: key += '_%s' % i
			i += 1
		
			tenants['computer_id_key'][key] = node.text

		for node in data:
			if not node.tag == 'TenantHostProtection': continue # only process computer information

			tenant_id = node.find('tenantName').text if not node.find('tenantName') == None else None
			if not tenants.has_key(tenant_id): tenants[tenant_id] = {}

			host_id = node.find('hostID').text if not node.find('hostID') == None else None
			tenants[tenant_id][host_id] = {
				'computer_id': host_id,
				'computer_id_1': node.find('hostID1').text if not node.find('hostID1') == None else None,
				'computer_id_2': node.find('hostID2').text if not node.find('hostID2') == None else None,
				'computer_id_3': node.find('hostID3').text if not node.find('hostID3') == None else None,
				'protection_start_date': dateutil.parser.parse(node.find('protectionStartDate').text) if not node.find('protectionStartDate') == None else None,
				'protection_stop_date': dateutil.parser.parse(node.find('protectionStopDate').text) if not node.find('protectionStopDate') == None else None,
				'total_seconds_protected': None,
				'total_protection_time': None,
				'tenant_id': node.find('tenantID').text if not node.find('tenantID') == None else None,
				'tenant_name': node.find('tenantName').text if not node.find('tenantName') == None else None,
			}

			# calculate seconds protected
			if tenants[tenant_id][host_id]['protection_start_date']:
				stop_time = datetime.datetime.utcnow()
				if tenants[tenant_id][host_id]['protection_stop_date']:
					stop_time = tenants[tenant_id][host_id]['protection_stop_date']

				protection_time = stop_time.replace(tzinfo=None) - tenants[tenant_id][host_id]['protection_start_date'].replace(tzinfo=None)
				tenants[tenant_id][host_id]['total_seconds_protected'] = protection_time.total_seconds()
				tenants[tenant_id][host_id]['total_protection_time'] = protection_time

		return tenants

	def get_tenant_overall_usage_information(self, tenant=None, from_timestamp=None, to_timestamp=None):
		"""
		@TODO: implement
		"""
		pass

	def get_intrusion_prevention_rules(self):
		"""
		Retrieve all of the intrusion prevention rules
		"""
		call = self._get_call_structure()
		call['method'] = 'DPIRuleRetrieveAll'
		call['data'] = {
							'sID': self.session_id_soap,
						}
		result = self._make_call(call)
		if result:
			for obj in result:
				self.rules['intrusion_prevention'][obj['ID']] = intrusion_prevention_rule.IntrusionPreventionRule(rule_details=obj, manager=self)

	def get_firewall_rules(self):
		"""
		Retrieve all of the firewall rules
		"""
		call = self._get_call_structure()
		call['method'] = 'firewallRuleRetrieveAll'
		call['data'] = {
							'sID': self.session_id_soap,
						}
		result = self._make_call(call)
		if result:
			for obj in result:
				self.rules['firewall'][obj['ID']] = firewall_rule.FirewallRule(rule_details=obj, manager=self)

	def get_integrity_monitoring_rules(self):
		"""
		Retrieve all of the integrity monitoring rules
		"""
		call = self._get_call_structure()
		call['method'] = 'integrityRuleRetrieveAll'
		call['data'] = {
							'sID': self.session_id_soap,
						}
		result = self._make_call(call)	
		if result:
			for obj in result:
				self.rules['integrity_monitoring'][obj['ID']] = integrity_monitoring_rule.IntegrityMonitoringRule(rule_details=obj, manager=self)

	def get_log_inspection_rules(self):
		"""
		Retrieve all of the log inspection rules
		"""
		call = self._get_call_structure()
		call['method'] = 'logInspectionRuleRetrieveAll'
		call['data'] = {
							'sID': self.session_id_soap,
						}
		result = self._make_call(call)
		if result:
			for obj in result:
				self.rules['log_inspection'][obj['ID']] = log_inspection_rule.LogInspectionRule(rule_details=obj, manager=self)

	def get_all_application_types(self):
		"""
		Retrieve all application types from the Deep Security rules database
		"""
		call = self._get_call_structure()
		call['method'] = 'applicationTypeRetrieveAll'
		call['data'] = {
							'sID': self.session_id_soap,
						}
		result = self._make_call(call)
		if result:
			for obj in result:
				self.application_types[obj['ID']] = application_type.ApplicationType(type_details=obj, manager=self)

	def get_all_rules(self):
		"""
		Retrieve all of the rules from the Deep Security Manager

		Calls;
		- get_intrusion_prevention_rules
		- get_firewall_rules
		- get_integrity_monitoring_rules
		- get_log_inspection_rules
		"""
		self.get_intrusion_prevention_rules()
		self.get_firewall_rules()
		self.get_integrity_monitoring_rules()
		self.get_log_inspection_rules()