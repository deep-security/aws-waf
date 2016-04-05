# standard library
import datetime

# 3rd party libraries

# project libraries
import core

class CloudAccounts(core.CoreDict):
  def __init__(self, manager=None):
    core.CoreDict.__init__(self)
    self.manager = manager
    self.log = self.manager.log if self.manager else None

  def get(self):
    """
    Get a list of all of the current configured cloud accounts
    """
    call = self.manager._get_request_format(api=self.manager.API_TYPE_REST, call='cloudaccounts')
    response = self.manager._request(call)
    if response and response['status'] == 200:
      if response['data'] and response['data'].has_key('cloudAccountListing') and response['data']['cloudAccountListing'].has_key('cloudAccounts'):
        for cloud_account in response['data']['cloudAccountListing']['cloudAccounts']:
          cloud_account_obj = CloudAccount(self.manager, cloud_account, self.log)
          self[cloud_account_obj.cloud_account_id] = cloud_account_obj

  def add_aws_account(self, name, aws_access_key=None, aws_secret_key=None, region="all"):
    """
    Add an AWS Cloud account to Deep Security
    """
    responses = {}

    regions = {
      'us-east-1': 'amazon.cloud.region.key.1',
      'us-west-1': 'amazon.cloud.region.key.2',
      'us-west-2': 'amazon.cloud.region.key.3',
      'eu-west-1': 'amazon.cloud.region.key.4',
      'ap-southeast-1': 'amazon.cloud.region.key.5',
      'ap-northeast-1': 'amazon.cloud.region.key.6',
      'sa-east-1': 'amazon.cloud.region.key.7',
    }

    regions_to_add = []
    if regions.has_key(region):
      regions_to_add.append(region)
    elif region == 'all':
      regions_to_add.append(regions.keys())
    else:
      self.log("A region must be specified when add an AWS account to Deep Security")

    for region_to_add in regions_to_add:
      call = self.manager._get_request_format(api=self.manager.API_TYPE_REST, call='cloudaccounts')
      call['data'] = {
        'createCloudAccountRequest': {
          'sessionId': self.manager._sessions[self.manager.API_TYPE_REST],
          'cloudAccountElement': {
              'accessKey': aws_access_key,
              'secretKey': aws_secret_key,
              'cloudType': 'AMAZON',
              'name': '{} / {}'.format(name, region_to_add),
              'cloudRegion': regions[region_to_add],
            },
          }
      }

      responses[region_to_add] = self.manager._request(call)
      if not responses[region_to_add] and responses[region_to_add]['status'] == 200:
        if responses[region_to_add]['raw'] and 'Cloud Account Region/Partition already present' in responses[region_to_add]['raw']:
          self.log("The account/region you request has already been added to Deep Security. A specific account/region combination can only be added once")

    return responses

class CloudAccount(core.CoreObject):
  def __init__(self, manager=None, api_response=None, log_func=None):
    self.manager = manager
    if api_response: self._set_properties(api_response, log_func)