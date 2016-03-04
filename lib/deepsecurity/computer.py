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
			'external': 'external',
      'externalID': 'external_id',
      'hostGroupID': 'host_group_id',
      'hostType': 'host_type',
			'platform': 'platform',
			'securityProfileID': 'policy_id',
			'antiMalwareClassicPatternVersion': 'anti_malware_classic_pattern_version',
      'antiMalwareEngineVersion': 'anti_malware_engine_version',
      'antiMalwareIntelliTrapExceptionVersion': 'anti_malware_intelli_trap_exception_version',
      'antiMalwareIntelliTrapVersion': 'anti_malware_intelli_trap_version',
      'antiMalwareSmartScanPatternVersion': 'anti_malware_smart_scan_pattern_version',
      'antiMalwareSpywarePatternVersion': 'anti_malware_spyware_pattern_version',
			'cloudObjectImageId': 'cloud_object_image_id', # @TODO handle property name change
			'cloudObjectInstanceId': 'cloud_object_instance_id', # @TODO handle property name change
			'cloudObjectInternalUniqueId': 'cloud_object_internal_unique_id',
			'cloudObjectSecurityGroupIds': 'cloud_security_policy',
			'cloudObjectType': 'cloud_type',
			'componentKlasses': 'component_klasses',
      'componentNames': 'component_names',
      'componentTypes': 'component_types',
      'componentVersions': 'component_versions',
      'hostGroupName': 'host_group_name',
      'hostInterfaces': 'host_interfaces',
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
      'lastAnitMalwareScheduledScan': 'last_anti_malware_scheduled_scan',
      'lastAntiMalwareEvent': 'last_anti_malware_event',
      'lastAntiMalwareManualScan': 'last_anti_malware_manual_scan',
      'lastDpiEvent': 'last_dpi_event',
      'lastFirewallEvent': 'last_firewall_event',
      'lastIPUsed': 'last_ip_used',
      'lastIntegrityMonitoringEvent': 'last_integrity_monitoring_event',
      'lastLogInspectionEvent': 'last_log_inspection_event',
      'lastWebReputationEvent': 'last_web_reputation_event',
      'light': 'light',
      'locked': 'locked',
      'overallLastRecommendationScan': 'overall_last_recommendation_scan',
      'overallLastSuccessfulCommunication': 'overall_last_successful_communication',
      'overallLastSuccessfulUpdate': 'overall_last_successful_update',
      'overallLastUpdateRequired': 'overall_last_update_required',
      'overallVersion': 'overall_version',
      'securityProfileName': 'security_profile_name',
      'virtualName': 'virtual_name',
      'virtualUuid': 'virtual_uuid',
			}.items():
			try:
				if key in dir(host_details):
					setattr(self, prop, host_details[key])
				else:
					self.manager.log("Property {} is not present in API response".format(key))
			except Exception, err:
				if self.manager: self.manager.log("Could not add property [%s] to computer [%s]. Threw exception: %s".format(prop, host_details['name'], err), err=err, level='warning')

		try:
			if 'has_key' in host_details and host_details.has_key('hostInterfaces') and host_details['hostInterfaces'] and type(host_details['hostInterfaces']) == type([]):
				self.number_of_interfaces = len(host_details['hostInterfaces'])
			else:
				self.number_of_interfaces = None
		except Exception, err:
			if self.manager: self.manager.log("Could not add property [number_of_interfaces] to computer [%s]. Threw exception: %s".format(host_details['name'], err), err=err, level='warning')

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