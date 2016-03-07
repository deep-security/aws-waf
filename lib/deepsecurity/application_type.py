class ApplicationType(object):
  def __init__(self, type_details, manager=None):
    self.manager = manager
    self.data = type_details
    self._process_type_detail(type_details)

  # *****************************************************************
  # 'Private' methods
  # *****************************************************************
  def _process_type_detail(self, type_details):
    """
    Convert the most useful type details returned from the API into
    top level properties
    """
    for key, prop in {
      'ID': 'id',
      'name': 'name',
      'description': 'description',
      'TBUID': 'tbuid',
      'authoritative': 'authoritative',
      'direction': 'direction',
      'ignoreRecommendations': 'ignore_recommendations',
      'protocolIcmp': 'protocol_icmp',
      'protocolPortBased': 'protocol_port_based',
      'protocolType': 'protocol_type',
      }.items():
      try:
        setattr(self, prop, type_details[key])
      except Exception, err:
        if self.manager: self.manager.log("Could not add property [%s] to rule [%s]. Threw exception: %s".format(prop, type_details['name'], err), err=err, level='warning')