class LogInspectionRule(object):
  def __init__(self, rule_details, manager=None):
    self.manager = manager
    self.data = rule_details
    self._process_rule_detail(rule_details)

  # *****************************************************************
  # 'Private' methods
  # *****************************************************************
  def _process_rule_detail(self, rule_details):
    """
    Convert the most useful rules details returned from the API into
    top level properties
    """
    for key, prop in {
      'ID': 'id',
      'name': 'name',
      'description': 'description',
      'TBUID': 'tbuid',
      'alertMinSeverity': 'alert_min_severity',
      'authoritative': 'authoritative',
      'content': 'content',
      'files': 'files',
      'identifier': 'identifier',
      'ignoreRecommendations': 'ignore_recommendations',
      'issued': 'issued',
      'minAgentVersion': 'min_agent_version',
      'minManagerVersion': 'min_manager_version',
      'raiseAlert': 'raise_alert',
      }.items():
      try:
        setattr(self, prop, rule_details[key])
      except Exception, err:
        if self.manager: self.manager.log("Could not add property [%s] to rule [%s]. Threw exception: %s".format(prop, rule_details['name'], err), err=err, level='warning')