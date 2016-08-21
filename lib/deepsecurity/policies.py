# standard library
import datetime

# 3rd party libraries

# project libraries
import core
import translation

class Policies(core.CoreDict):
  def __init__(self, manager=None):
    core.CoreDict.__init__(self)
    self.manager = manager
    self.log = self.manager.log if self.manager else None

  def get(self):
    """
    Get all of the policies from Deep Security
    """
    call = self.manager._get_request_format(call='securityProfileRetrieveAll')
    response = self.manager._request(call)
    
    if response and response['status'] == 200:
      if not type(response['data']) == type([]): response['data'] = [response['data']]
      for policy in response['data']:
        policy_obj = Policy(manager=self.manager, api_response=policy, log_func=self.log)
        if policy_obj:
          try:
            self[policy_obj.id] = policy_obj
            self.log("Added Policy {}".format(policy_obj.id), level='debug')
          except Exception, err:
            self.log("Could not add Policy {}".format(policy_obj), level='warning', err=err)

    return len(self)

  def create(self, name, parent_profile_id=None,
              enable_anti_malware=True,
              enable_firewall=False,
              enable_intrusion_prevention=True,
              enable_integrity_monitoring=True,
              enable_log_inspection=True,
              description=None
              ):
    """
    Create a new policy

    name
      - the name of the new policy

    parent_profile_id
      - the ID of the parent policy

    enable_anti_malware
      - if True, enable the anti-malware module
      - if 'parent_profile_id' is set, the new policy will 
        inherit this value from the parent

    enable_firewall
      - if True, enable the firewall module
      - if 'parent_profile_id' is set, the new policy will 
        inherit this value from the parent

    enable_intrusion_prevention
      - if True, enable the intrusion prevention module
      - if 'parent_profile_id' is set, the new policy will 
        inherit this value from the parent

    enable_integrity_monitoring
      - if True, enable the integrity monitoring module
      - if 'parent_profile_id' is set, the new policy will 
        inherit this value from the parent   

    enable_log_inspection
      - if True, enable the log inspection module
      - if 'parent_profile_id' is set, the new policy will 
        inherit this value from the parent  

    description
      - the description of the new policy

    Returns the ID of the new policy is successful. False if not successful in 
    creating the new policy
    """
    result = None

    # set the state for each supported module
    anti_malware_state = 'ON' if enable_anti_malware else 'OFF'
    firewall_state = 'ON' if enable_firewall else 'OFF'
    intrusion_prevention_state = 'ON' if enable_intrusion_prevention else 'OFF'
    integrity_monitoring_state = 'ON' if enable_integrity_monitoring else 'OFF'
    log_inspection_state = 'ON' if enable_log_inspection else 'OFF'

    # inherit all states if a parent policy is specified
    if parent_profile_id:
      anti_malware_state = 'INHERITED'
      firewall_state = 'INHERITED'
      intrusion_prevention_state = 'INHERITED'
      integrity_monitoring_state = 'INHERITED'
      log_inspection_state = 'INHERITED'

    call = self.manager._get_request_format(call='securityProfileSave')
    call['data'] = { 'sp': {
             'DPIRuleIDs': None,
             'DPIState': intrusion_prevention_state,
             'ID': None,
             'antiMalwareManualID': None,
             'antiMalwareManualInherit': u'true',
             'antiMalwareRealTimeID': None,
             'antiMalwareRealTimeInherit': u'true',
             'antiMalwareRealTimeScheduleID': None,
             'antiMalwareScheduledID': None,
             'antiMalwareScheduledInherit': u'true',
             'antiMalwareState': anti_malware_state,
             'applicationTypeIDs': None,
             'description': description,
             'firewallRuleIDs': None,
             'firewallState': firewall_state,
             'integrityRuleIDs': None,
             'integrityState': integrity_monitoring_state,
             'logInspectionRuleIDs': None,
             'logInspectionState': log_inspection_state,
             'name': name,
             'parentSecurityProfileID': parent_profile_id if parent_profile_id else None,
             'recommendationState': None,
             'scheduleID': None,
             'statefulConfigurationID': None
             }
      }
    
    response = self.manager._request(call)
    if response and response['status'] == 200:
      try:
        new_policy = Policy(api_response=response['data'], manager=self.manager, log_func=self.log)
        if new_policy:
          self[new_policy.id] = new_policy
          result = new_policy.id
          self.log("Added new policy #{}".format(new_policy.id))
      except Exception, err:
        self.log("Could not create new policy from API response", err=err)
    else:
      result = False

    return result

class Rules(core.CoreDict):
  def __init__(self, manager=None):
    core.CoreDict.__init__(self)
    self.manager = manager
    self.log = self.manager.log if self.manager else None

  def get(self, intrusion_prevention=True, firewall=True, integrity_monitoring=True, log_inspection=True, web_reputation=True, application_types=True):
    """
    Get all of the rules from Deep Security
    """
    # determine which rules to get from the Manager()
    rules_to_get = {
      'DPIRuleRetrieveAll': intrusion_prevention,
      'firewallRuleRetrieveAll': firewall,
      'integrityRuleRetrieveAll': integrity_monitoring,
      'logInspectionRuleRetrieveAll': log_inspection,
      'applicationTypeRetrieveAll': application_types,
      }

    for call, get in rules_to_get.items():
      rule_key = translation.Terms.get(call).replace('_retrieve_all', '').replace('_rule', '')
      self[rule_key] = core.CoreDict()

      if get:
        soap_call = self.manager._get_request_format(call=call)
        if call == 'DPIRuleRetrieveAll':
          self.log("Calling {}. This may take 15-30 seconds as the call returns a substantial amount of data".format(call), level='warning')

        response = self.manager._request(soap_call)
        if response and response['status'] == 200:
          if not type(response['data']) == type([]): response['data'] = [response['data']]
          for i, rule in enumerate(response['data']):
            rule_obj = Rule(self.manager, rule, self.log, rule_type=rule_key)
            if rule_obj:
              if rule_key == 'intrusion_prevention' and rule_obj.cve_numbers:
                rule_obj.cve_numbers = rule_obj.cve_numbers.split(', ')
                if type(rule_obj.cve_numbers) in [type(''), type(u'')]: rule_obj.cve_numbers = [ rule_obj.cve_numbers ]
                
              rule_id = '{}-{: >10}'.format(rule_key, i)
              if 'id' in dir(rule_obj): rule_id = rule_obj.id
              elif 'tbuid' in dir(rule_obj): rule_id = rule_obj.tbuid
              self[rule_key][rule_id] = rule_obj
              self.log("Added Rule {} from call {}".format(rule_id, call), level='debug')

    return len(self)

class IPLists(core.CoreDict):
  def __init__(self, manager=None):
    core.CoreDict.__init__(self)
    self.manager = manager
    self.log = self.manager.log if self.manager else None

  def get(self):
    """
    Get all of the IP Lists from Deep Security
    """
    soap_call = self.manager._get_request_format(call='IPListRetrieveAll')
    response = self.manager._request(soap_call)
    if response and response['status'] == 200:
      for ip_list in response['data']:
        ip_list_obj = IPList(self.manager, ip_list, self.log)
        self[ip_list_obj.id] = ip_list_obj
    
    return len(self)

class Policy(core.CoreObject):
  def __init__(self, manager=None, api_response=None, log_func=None):
    self.manager = manager
    self.computers = core.CoreDict()
    self.rules = core.CoreDict()
    if api_response: self._set_properties(api_response, log_func)
    #self._flatten_rules()

  def _flatten_rules(self):
    """
    Flatten the various module rules into a master list
    """
    for rule_type in [
      'intrusion_prevention_rule_ids',
      'firewall_rule_ids',
      'integrity_monitoring_rule_ids',
      'log_inspection_rule_ids',
      ]:
      rules = getattr(self, rule_type)
      if rules:
        for rule in rules['item']:
          self.rules['{}-{}'.format(rule_type.replace('rule_ids', ''), rule)] = None

  def save(self):
    """
    Save any changes made to the policy
    """
    result = False

    soap_call = self.manager._get_request_format(call='securityProfileSave')
    soap_call['data'] = { 'sp': self.to_dict() }

    if soap_call['data']['sp'].has_key('manager'):
      del(soap_call['data']['sp']['manager'])

    response = self.manager._request(soap_call)
    if response['status'] == 200:
      result = True
    else:
      result = False
      if 'log' in dir(self):
        self.log("Could not save the policy. Returned: {}".format(response), level='error')

    return result

  def get_application_control_settings(self):
    """
    Get the details for the application control settings for this policy
    """
    return self.manager.application_control.get_policy_settings(self.id)

  def set_application_control_settings(self, policy_id, lockdown=None, ruleset_id=None, state=None, whitelist_mode=None):
    """
    Set the details for the application control settings for this policy

    lockdown:
      - if set to None, no changes are made
      - if set to True, lockdown mode is enabled and anything that's not on the whitelist will be blocked
      - if set to False, lockdown mode is disabled and only things on the blacklist will be blocked

    ruleset_id:
      - if set to None, no changes are made
      - the ID of the ruleset to use for this application control policy

    state:
      - if set to None, no changes are made 
      - if set to "on", application control is turned on for this policy
      - if set to "off", application control is turned off for this policy
      - if set to "inherit", the application control state inherited from this policy's parent (if one exists)  

    whitelist_mode:
      - if set to None, no changes are made
      - if set to "local-inventory", application control is turned on for this policy
      - if set to "shared", application control is turned off for this policy
      - if set to "inherit", the application control state inherited from this policy's parent (if one exists)  
    """    
    return self.manager.application_control.set_policy_settings(self.id, lockdown=lockdown, ruleset_id=ruleset_id, state=state, whitelist_mode=whitelist_mode)

class Rule(core.CoreObject):
  def __init__(self, manager=None, api_response=None, log_func=None, rule_type=None):
    self.manager = manager
    self.rule_type = rule_type
    self.policies = core.CoreDict()
    if api_response: self._set_properties(api_response, log_func)  

class IPList(core.CoreObject):
  def __init__(self, manager=None, api_response=None, log_func=None):
    self.manager = manager
    self.addresses = []
    if api_response: self._set_properties(api_response, log_func)
    self._split_items()

  def _split_items(self):
    """
    Split the individual items in an IP List into entries
    """
    if getattr(self, 'items') and "\n" in self.items:
      self.addresses = self.items.split('\n')
    else:
      self.addresses.append(self.items.strip())