class Computer(object):
	def __init__(self, host_details, manager=None):
		self.manager = manager
		self.data = host_details
		self._process_host_detail(host_details)

	# *****************************************************************
	# 'Private' methods
	# *****************************************************************
	def _process_host_detail(self, host_details):
		"""
		Convert the most useful host details returned from the API into
		top level properties
		"""
		for key, prop in {
			'ID': 'id',
			'name': 'hostname',
			'description': 'description',
			'displayName': 'display_name',
			'platform': 'platform',
			'securityProfileID': 'policy_id',
			'cloudObjectImageId': 'cloud_image_id',
			'cloudObjectInstanceId': 'cloud_instance_id',
			'cloudObjectSecurityGroupIds': 'cloud_security_policy',
			'cloudObjectType': 'cloud_type',
			'hostLight': 'status_light',
			'securityProfileName': 'policy_name',
			'lastIPUsed': 'last_ip',
			'overallAntiMalwareStatus': 'module_status_anti_malware',
			'overallDpiStatus': 'module_status_ips',
			'overallFirewallStatus': 'module_status_firewall',
			'overallIntegrityMonitoringStatus': 'module_status_integrity_monitoring',
			'overallLogInspectionStatus': 'module_status_log_inspection',
			'overallWebReputationStatus': 'module_status_web_reputation',
			'overallStatus': 'overall_status',
			}.items():
			try:
				setattr(self, prop, host_details[key])
			except Exception, err:
				if self.manager: self.manager.log.warning("Could not add property [%s] to computer [%s]. Threw exception: %s" % (prop, host_details['name'], err))

		try:
			self.number_of_interfaces = len(host_details['hostInterfaces'])
		except Exception, err:
			if self.manager: self.manager.log.warning("Could not add property [number_of_interfaces] to computer [%s]. Threw exception: %s" % (host_details['name'], err))

	# *****************************************************************
	# Public methods
	# *****************************************************************
	def send_events_to_manager(self):
		"""
		Ask the computer to send the latest events it's seen to the DSM
		"""
		if not self.manager: return None

		self.manager.request_events_from_computer(host_id=self.data['ID'])
		# None is returned if the call worked so we have no way of checking
		# if this worked or didn't

	def clear_warnings_and_errors(self):
		"""
		Clear any warnings or errors currently showing
		"""
		if not self.manager: return None

		self.manager.clear_warnings_and_errors_from_computer(host_ids=self.data['ID'])
		# None is returned if the call worked so we have no way of checking
		# if this worked or didn't

	def scan_for_malware(self):
		"""
		Request a malware scan be run immediately
		"""
		if not self.manager: return None

		self.manager.scan_computers_for_malware(host_ids=self.data['ID'])
		# None is returned if the call worked so we have no way of checking
		# if this worked or didn't

	def scan_for_integrity(self):
		"""
		Request a integrity scan be run immediately
		"""
		if not self.manager: return None

		self.manager.scan_computers_for_integrity(host_ids=self.data['ID'])
		# None is returned if the call worked so we have no way of checking
		# if this worked or didn't

	def scan_for_recommendations(self):
		"""
		Request a recommendation scan be run immediately
		"""
		if not self.manager: return None

		self.manager.scan_computers_for_recommendations(host_ids=self.data['ID'])
		# None is returned if the call worked so we have no way of checking
		# if this worked or didn't	

	def assign_policy(self, policy_id):
		"""
		Assign a security policy to the computer
		"""
		if not self.manager: return None

		self.manager.assign_policy_to_computers(policy_id=policy_id, host_ids=self.data['ID'])
		# None is returned if the call worked so we have no way of checking
		# if this worked or didn't

	def __str__(self):
		"""
		Return a better string representation
		"""
		if 'cloud_instance_id' in dir(self) and 'hostname' in dir(self):
			return '{} <{}>'.format(self.hostname, self.cloud_instance_id)
		elif 'hostname' in dir(self):
			return self.hostname
		else:
			return "Computer [{}]".format(self.data['ID'])