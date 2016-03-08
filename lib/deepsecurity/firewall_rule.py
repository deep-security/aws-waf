class FirewallRule(object):
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
      'action': 'action',
      'anyFlags': 'any_flags',
      'destinationIP': 'destination_ip',
      'destinationIPListID': 'destination_ip_list_id',
      'destinationIPMask': 'destination_ip_mask',
      'destinationIPNot': 'destination_ip_not',
      'destinationIPRangeFrom': 'destination_ip_range_from',
      'destinationIPRangeTo': 'destination_ip_range_to',
      'destinationIPType': 'destination_ip_type',
      'destinationMAC': 'destination_mac',
      'destinationMACListID': 'destination_mac_list_id',
      'destinationMACNot': 'destination_mac_not',
      'destinationMACType': 'destination_mac_type',
      'destinationPortListID': 'destination_port_list_id',
      'destinationPortNot': 'destination_port_not',
      'destinationPortType': 'destination_port_type',
      'destinationPorts': 'destination_ports',
      'destinationSingleIP': 'destination_single_ip',
      'disabledLog': 'disabled_log',
      'frameNot': 'frame_not',
      'frameNumber': 'frame_number',
      'frameType': 'frame_type',
      'icmpCode': 'icmp_code',
      'icmpNot': 'icmp_not',
      'icmpType': 'icmpType',
      'packetDirection': 'packet_direction',
      'priority': 'priority',
      'protocolNot': 'protocol_not',
      'protocolNumber': 'protocol_number',
      'protocolType': 'protocol_type',
      'raiseAlert': 'raise_alert',
      'scheduleID': 'schedule_id',
      'sourceIP': 'source_ip',
      'sourceIPListID': 'source_ip_list_id',
      'sourceIPMask': 'source_ip_mask',
      'sourceIPNot': 'source_ip_not',
      'sourceIPRangeFrom': 'source_ip_range_from',
      'sourceIPRangeTo': 'source_ip_range_to',
      'sourceIPType': 'source_ip_type',
      'sourceMAC': 'source_mac',
      'sourceMACListID': 'source_mac_list_id',
      'sourceMACNot': 'source_mac_not',
      'sourceMACType': 'source_mac_type',
      'sourcePortListID': 'source_port_list_id',
      'sourcePortNot': 'source_port_not',
      'sourcePortType': 'source_port_type',
      'sourcePorts': 'source_ports',
      'sourceSingleIP': 'source_single_ip',
      'tcpFlagACK': 'tcp_flag_ack',
      'tcpFlagFIN': 'tcp_flag_fin',
      'tcpFlagPSH': 'tcp_flag_psh',
      'tcpFlagRST': 'tcp_flag_rst',
      'tcpFlagSYN': 'tcp_flag_syn',
      'tcpFlagURG': 'tcp_flag_urg',
      'tcpNot': 'tcp_not',
      }.items():
      try:
        setattr(self, prop, rule_details[key])
      except Exception, err:
        if self.manager: self.manager.log("Could not add property [%s] to rule [%s]. Threw exception: %s".format(prop, rule_details['name'], err), err=err, level='warning')