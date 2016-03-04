class IntrusionPreventionRule(object):
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
      'applicationTypeID': 'application_type_id',
      'authoritative': 'authoritative',
      'cvssScore': 'cvss_score',
      'detectOnly': 'detect_only',
      'disableEvent': 'disable_event',
      'eventOnPacketDrop': 'event_on_packet_drop',
      'eventOnPacketModify': 'event_on_packet_modify',
      'identifier': 'identifier',
      'ignoreRecommendations': 'ignore_recommendations',
      'includePacketData': 'include_packet_data',
      'issued': 'issued',
      'patternAction': 'pattern_action',
      'patternCaseSensitive': 'pattern_case_sensitive',
      'patternEnd': 'pattern_end',
      'patternIf': 'pattern_if',
      'patternPatterns': 'pattern_patterns',
      'patternStart': 'pattern_start',
      'priority': 'priority',
      'raiseAlert': 'raise_alert',
      'ruleXML': 'rule_xml',
      'scheduleID': 'schedule_id',
      'severity': 'severity',
      'signatureAction': 'signature_action',
      'signatureCaseSensitive': 'signature_case_sensitive',
      'templateType': 'template_type',
      'cveNumbers': 'cve_numbers',
      'msNumbers': 'ms_numbers',
      }.items():
      try:
        setattr(self, prop, rule_details[key])
      except Exception, err:
        if self.manager: self.manager.log("Could not add property [%s] to rule [%s]. Threw exception: %s".format(prop, rule_details['name'], err), err=err, level='warning')