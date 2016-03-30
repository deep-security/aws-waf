# standard library

# 3rd party libraries

# project libraries

class Terms:
  api_to_new = {
    'id': 'id',
    'dpistate': 'intrusion_prevention_state',
    'overallintegritymonitoringstatus': 'overall_integrity_monitoring_status',
    'cloudobjecttype': 'cloud_type',
    'overalllastupdaterequired': 'overall_last_update_required',
    'loginspectionruleids': 'log_inspection_rule_ids',
    'statefulconfigurationid': 'stateful_configuration_id',
    'integrityruleids': 'integrity_monitoring_rule_ids',
    'tbuid': 'tbuid',
    'componentversions': 'component_version',
    'externalid': 'external_id',
    'overalllastsuccessfulupdate': 'overall_last_successful_update',
    'parentgroupid': 'parent_group_id',
    'dpiruleids': 'intrusion_prevention_rule_ids',
    'overallantimalwarestatus': 'overall_anti_malware_status',
    'lastantimalwaremanualscan': 'last_anti_malware_manual_scan',
    'overalldpistatus': 'overall_intrusion_prevention_status',
    'hostlight': 'computer_status_light',
    'antimalwarespywarepatternversion': 'anti_malware_spyware_pattern_version',
    'antimalwareclassicpatternversion': 'anti_malware_classic_pattern_version',
    'antimalwarescheduledid': 'anti_malware_scheduled_id',
    'cloudobjectimageid': 'cloud_image_id',
    'antimalwarerealtimeinherit': 'anti_malware_real_time_inherit',
    'antimalwareintellitrapversion': 'anti_malware_intellitrap_version',
    'applicationtypeids': 'application_type_ids',
    'componentnames': 'component_names',
    'antimalwarerealtimescheduleid': 'anti_malware_real_time_schedule_id',
    'overalllastrecommendationscan': 'overall_last_recommendation_scan',
    'overalllastsuccessfulcommunication': 'overall_last_successful_communication',
    'lastipused': 'last_ip_used',
    'integrityruleids': 'integrity_monitoring_rule_ids',
    'recommendationstate': 'recommedation_state',
    'lastantimalwareevent': 'last_anti_malware_event',
    'antimalwaremanualinherit': 'anti_malware_manual_inherit',
    'lastanitmalwarescheduledscan': 'last_anti_malware_scheduled_scan',
    'overallfirewallstatus': 'overall_firewall_status',
    'cloudobjectinstanceid': 'cloud_instance_id',
    'antimalwaremanualid': 'anti_malware_manual_id',
    'lastwebreputationevent': 'last_content_filtering_event',
    'antimalwareintellitrapexceptionversion': 'anti_malware_intellitrap_exception_version',
    'overallloginspectionstatus': 'overall_log_inspection_status',
    'componentklasses': 'component_classes',
    'componenttypes': 'component_types',
    'antimalwarescheduledinherit': 'anti_malware_scheduled_inherit',
    'antimalwarerealtimeid': 'anti_malware_real_time_id',
    'virtualuuid': 'virtual_uuid',
    'hostinterfaces': 'computer_interfaces',
    'parentsecurityprofileid': 'parent_policy_id',
    'cloudobjectsecuritygroupids': 'cloud_security_group_ids',
    'overallversion': 'overall_version',
    'cloudobjectinternaluniqueid': 'cloud_internal_unique_id',
    'hostgroupid': 'computer_group_id',
    'lastintegritymonitoringevent': 'last_integrity_monitoring_event',
    'integritystate': 'integrity_monitoring_state',
    'hostgroupname': 'computer_group_name',
    'antimalwarestate': 'anti_malware_state',
    'antimalwareengineversion': 'anti_malware_engine_version',
    'scheduleid': 'schedule_id',
    'securityprofilename': 'policy_name',
    'displayname': 'display_name',
    'lastloginspectionevent': 'last_log_inspection_event',
    'lastfirewallevent': 'last_firewall_event',
    'firewallstate': 'firewall_state',
    'virtualname': 'virtual_name',
    'loginspectionruleids': 'log_inspection_rule_ids',
    'loginspectionstate': 'log_inspection_state',
    'hosttype': 'computer_type',
    'antimalwaresmartscanpatternversion': 'anti_malware_smartscan_pattern_version',
    'lastdpievent': 'last_intrusion_prevention_event',
    'securityprofileid': 'policy_id',
    'overallwebreputationstatus': 'overall_content_filtering_status',
    'firewallruleids': 'firewall_rule_ids',
    'overallstatus': 'overall_status',
    'firewallruleids': 'firewall_rule_ids',
    'dpiruleretrieveall': 'intrusion_prevention_rule_retrieve_all',
    'firewallruleretrieveall': 'firewall_rule_retrieve_all',
    'integrityruleretrieveall': 'integrity_monitoring_rule_retrieve_all',
    'loginspectionruleretrieveall': 'log_inspection_rule_retrieve_all',
    'applicationtyperetrieveall': 'application_type_retrieve_all',
    }

  @classmethod
  def get_reverse(self, new_term):
    result = new_term
    for api, new in Terms.api_to_new.items():
      if new == new_term:
        result = api

    return result

  @classmethod
  def get(self, api_term):
    """
    Return the translation of the specified API term
    """
    if Terms.api_to_new.has_key(api_term.lower()):
      return self.api_to_new[api_term.lower()]
    else:
      return api_term