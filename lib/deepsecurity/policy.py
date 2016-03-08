class Policy:
	"""
	Represents a Deep Security security policy
	"""
	def __init__(self, policy_details, manager=None):
		self.manager = manager
		self.data = policy_details
		self._parse_details(policy_details)

	def __str__(self):
		if self.id and self.name:
			return "Policy {} <{}>".format(self.id, self.name)
		elif self.id:
			return "Policy {}".format(self.id)
		else:
			return self.__name__

	def _parse_details(self, policy_details):
		for k, v in {
			   'ID': 'id',
			   'description': 'description',
			   'name': 'name',
			   'DPIRuleIDs': 'intrusion_prevention_rules',
			   'DPIState': 'intrusion_prevention_state',
			   'antiMalwareManualID': 'anti_malware_manual_schedule',
			   'antiMalwareManualInherit': 'anti_malware_manual_is_inherited',
			   'antiMalwareRealTimeID': 'anti_malware_realtime_id',
			   'antiMalwareRealTimeInherit': 'anti_malware_realtime_is_inherited',
			   'antiMalwareRealTimeScheduleID': 'anti_malware_realtime_schedule',
			   'antiMalwareScheduledID': 'anti_malware_schedule',
			   'antiMalwareScheduledInherit': 'anti_malware_is_inherited',
			   'antiMalwareState': 'anti_malware_state',
			   'applicationTypeIDs': 'application_types',
			   'firewallRuleIDs': 'firewall_rules',
			   'firewallState': 'firewall_state',
			   'integrityRuleIDs': 'integrity_monitoring_rules',
			   'integrityState': 'integrity_state',
			   'logInspectionRuleIDs': 'log_inspection_rules',
			   'logInspectionState': 'log_inspection_state',
			   'parentSecurityProfileID': 'parent_id',
			   'recommendationState': 'recommendation_state',
			   'scheduleID': 'schedule',
			   'statefulConfigurationID': 'None',
			}.items():
			try:
				setattr(self, v, getattr(policy_details, k))
			except Exception, err:
				self.log("Could not set attribute [{}] for Policy".format(v), exception=err)