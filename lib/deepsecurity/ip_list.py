class IpList:
	"""
	Represents a Deep Security IP list
	"""
	def __init__(self, ip_list_details, manager=None):
		self.manager = manager
		self.data = ip_list_details
		self._parse_details(ip_list_details)		
		self.addresses = []
		self._split_items()

	def __str__(self):
		if self.id and self.name:
			return "IpList {} <{}>".format(self.id, self.name)
		elif self.id:
			return "IpList {}".format(self.id)
		else:
			return self.__name__

	def _parse_details(self, ip_list_details):
		for k, v in {
			'ID': 'id',
			'description': 'description',
			'name': 'name',
			'items': 'items',
			}.items():
			try:
				setattr(self, v, getattr(ip_list_details, k))
			except Exception, err:
				if self.manager: self.manager.log("Could not set attribute [{}] for IpList".format(v))

	def _split_items(self):
		if getattr(self, 'items') and "\n" in self.items:
			self.addresses = self.items.split('\n')
		else:
			self.addresses.append(self.items.strip())