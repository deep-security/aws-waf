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
        policy_obj = Policy(self.manager, policy, self.log)
        if policy_obj:
          try:
            self[policy_obj.id] = policy_obj
            self.log("Added Policy {}".format(policy_obj.id), level='debug')
          except Exception, err:
            self.log("Could not add Policy {}".format(policy_obj), level='warning', err=err)

    return len(self)

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

class Rule(core.CoreObject):
  def __init__(self, manager=None, api_response=None, log_func=None, rule_type=None):
    self.manager = manager
    self.rule_type = rule_type
    self.policies = core.CoreDict()
    if api_response: self._set_properties(api_response, log_func)  

class IPList(core.CoreObject):
  def __init__(self, manager=None, api_response=None, log_func=None, rule_type=None):
    self.manager = manager
    self.rule_type = rule_type
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