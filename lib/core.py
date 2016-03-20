# standard libraries
import argparse
import os
import urllib2

# 3rd party libraries
import boto3
import boto3.session

# project libraries
import deepsecurity

def get_arg_parser(prog='ds-to-aws-waf.py', description=None, add_help=False):
  """
  Create a standardized argument parser
  """
  if not description:
    description = """
    Create and update AWS WAF WACL rules based on information from a Deep Security installation
"""

  parser = argparse.ArgumentParser(prog=prog, description=description, add_help=add_help)

  # Deep Security arguments
  parser.add_argument('-d', '--dsm', action='store', default='app.deepsecurity.trendmicro.com', required=False, help='The address of the Deep Security Manager. Defaults to Deep Security as a Service')
  parser.add_argument('--dsm-port', action='store', default='4119', dest='dsm_port', required=False, help='The address of the Deep Security Manager. Defaults to an AWS Marketplace/software install (:4119). Automatically configured for Deep Security as a Service')
  parser.add_argument('-u', '--dsm-username', action='store', dest='dsm_username', required=True, help='The Deep Security username to access the IP Lists with. Should only have read-only rights to IP lists and API access')
  parser.add_argument('-p', '--dsm-password', action='store', dest='dsm_password', required=True, help='The password for the specified Deep Security username. Should only have read-only rights to IP lists and API access')
  parser.add_argument('-t', '--dsm-tenant', action='store', dest='dsm_tenant', required=False, default=None, help='The name of the Deep Security tenant/account')

  # AWS arguments
  parser.add_argument('-a', '--aws-access-key', action='store', dest='aws_access_key', required=False, help='The access key for an IAM identity in the AWS account to connect to')
  parser.add_argument('-s', '--aws-secret-key', action='store', dest='aws_secret_key', required=False, help='The secret key for an IAM identity in the AWS account to connect to')
  parser.add_argument('-r', '--aws-region', action='store', dest='aws_region', required=False, default='us-east-1', help='The name of AWS region to connect to')

  # general structure arguments
  parser.add_argument('--ignore-ssl-validation', action='store_true', dest='ignore_ssl_validation', required=False, help='Ignore SSL certification validation. Be careful when you use this as it disables a recommended security check. Required for Deep Security Managers using a self-signed SSL certificate')
  parser.add_argument('--dryrun', action='store_true', required=False, help='Do a dry run of the command. This will not make any changes to your AWS WAF service')
  parser.add_argument('--verbose', action='store_true', required=False, help='Enabled verbose output for the script. Useful for debugging')

  return parser

class StoreNameValuePairOnEquals(argparse.Action):
  """
  Store a set of name value pairs as an argument
  """
  def __init__(self, option_strings, dest, nargs=None, const=None, default=None, type=None, choices=None, required=False, help=None, metavar=None):
    self.dest = dest
    argparse.Action.__init__(self, option_strings, dest, nargs=nargs, const=const, default=default, type=type, choices=choices, required=required, help=help, metavar=metavar)

  # cribbed from http://stackoverflow.com/questions/5154716/using-argparse-to-parse-arguments-of-form-arg-val
  # response by @chepner (http://stackoverflow.com/users/1126841/chepner)
  def __call__(self, parser, namespace, values, dest, option_string=None):#
    pairs = {}
    for val in values:
      if '=' in val:
        n, v = val.split('=')
        pairs[n] = v # matches key:pair
      else:
        pairs[v] = '' # matches key:

    attr_key = option_string.strip('-') if option_string else ""
    if self.dest: attr_key = self.dest
    
    current_pairs = getattr(namespace, attr_key)
    if attr_key in dir(namespace) and current_pairs != None:
      new_pairs = current_pairs.copy()
      new_pairs.update(pairs)
      setattr(namespace, attr_key, new_pairs)
    else:
      setattr(namespace, attr_key, pairs)
    
class ScriptContext():
  """
  Context for a command line script.

  Using an object makes is easy to avoid any globals and clarifies 
  the intention of the script
  """
  def __init__(self, args, parser):
    self.parser = parser
    self._passed_args = args
    self.args = parser.parse_args(self._passed_args)
    self.dsm = None

  def __del__(self): self.clean_up() # clean up on object destruction

  def clean_up(self):
    """
    Gracefully dispose of the script's context
    """
    if 'dsm' in dir(self) and self.dsm:
      try:
        self.dsm.finish_session()
      except Exception, err: pass

  def update_user(self, message):
    """
    Update the update
    """
    print(message)

  def _log(self, msg, err=None, priority=False):
    """
    Create a log entry for the specified event
    """
    # @TODO add actual logging :-)
    if priority or self.args.verbose or err:
      if err:
        print("{}. Threw an exception:\n{}".format(msg, err))
      else:
        print(msg)

  def print_help(self):
    """
    Print the command line syntax available to the user
    """
    self.parser.print_help()

  def _get_aws_credentials(self):
    """
    Get a set of AWS credentials from a pre-configured AWS CLI installation
    """
    credentials = None

    # were credentials directly passed?
    if (self.args.aws_access_key and not self.args.aws_secret_key) or (self.args.aws_secret_key and not self.args.aws_access_key):
      self._log("When specifying AWS credentials via command line arguments both an access key and a secret key are required", priority=True)
    elif self.args.aws_access_key and self.args.aws_secret_key:
      self._log("Using AWS credentials specified via command line arguments")
      credentials = {
        'aws_access_key_id': self.args.aws_access_key,
        'aws_secret_access_key': self.args.aws_secret_key,
        }
    else:
      # check locally for an AWS CLI installation
      aws_credentials_path = [ '{}/.aws/credentials'.format(os.environ['HOME']), "{}\.aws\credentials".format(os.environ['HOME']) ]
      for path in aws_credentials_path:
        if os.path.exists(path) and not credentials:
          self._log("Reading AWS credentials from {}".format(path))
          with open(path) as fh:
            for line in fh:
              if line.startswith('aws_access_key_id'):
                credentials = { 'aws_access_key_id': line.split('=')[-1].strip() }
              elif line.startswith('aws_secret_access_key'):
                credentials['aws_secret_access_key'] = line.split('=')[-1].strip()

    return credentials

  def _connect_to_deep_security(self):
    dsm = None
    if self.args.ignore_ssl_validation:
      self._log("""************************************************************************
* IGNORING SSL CERTIFICATE VALIDATION
* ===================================
* You have requested to ignore SSL certificate validation. This is a 
* less secure method of connecting to a Deep Security Manager (DSM). 
* Please ensure that you have other mitigations and security controls 
* in place (like restricting IP space that can access the DSM, 
* implementing least privilege for the Deep Security user/role 
* accessing the API, etc).
*
* During script execution, you'll see a number of 
* "InsecureRequestWarning" messages. These are to be expected when 
* operating without validation. 
************************************************************************""", priority=True)
    try:
      dsm_port = self.args.dsm_port if not self.args.dsm == 'app.deepsecurity.trendmicro.com' else 443
      self._log("Attempting to connect to Deep Security at {}:{}".format(self.args.dsm, dsm_port))
      dsm = deepsecurity.manager.Manager(dsm_hostname=self.args.dsm, dsm_port=dsm_port, username=self.args.dsm_username, password=self.args.dsm_password, tenant=self.args.dsm_tenant, ignore_ssl_validation=self.args.ignore_ssl_validation) 
      self._log("Connected to the Deep Security Manager at {}".format(self.args.dsm))
    except Exception, err: 
      self._log("Could not connect to the Deep Security", err=err)

    if not dsm.session_id_rest and not dsm.session_id_soap:
      self._log("Unable to connect to the Deep Security Manager. Please check your settings")
      if not self.args.ignore_ssl_validation:
        self._log("You did not ask to ignore SSL certification validation. This is a common error when connect to a Deep Security Manager that was installed via software or the AWS Marketplace. Please set the flag (--ignore-ssl-validation), check your other settings, and try again")

    return dsm 

  def _connect_to_aws_service(self, service_name):
    """
    Connect to the specified AWS service via explicit credentials
    (shared by the AWS CLI) or an instance role
    """
    service = None
    try:
      aws = boto3.session.Session(aws_access_key_id=self.aws_credentials['aws_access_key_id'], aws_secret_access_key=self.aws_credentials['aws_secret_access_key'], region_name=self.args.aws_region)
      service = aws.client(service_name) 
      self._log("Connected to AWS {}".format(service_name))
    except Exception, err: 
      self._log("Could not connect to AWS {} using local CLI credentials".format(service_name), err=err)
      try:
        service = boto3.client(service_name)
        self._log("Connected to AWS {}".format(service_name))
      except Exception, err:
        self._log("Could not connect to AWS {} using an instance role".format(service_name), err=err)  

    return service

  def _connect_to_aws_waf(self): return self._connect_to_aws_service('waf')
  def _connect_to_aws_ec2(self): return self._connect_to_aws_service('ec2')
  def _connect_to_aws_elb(self): return self._connect_to_aws_service('elb')
  def _connect_to_aws_cloudfront(self): return self._connect_to_aws_service('cloudfront')

  def get_available_aws_sets(self):
    """
    Get a list of the available IP Sets in AWS WAF
    """
    ip_sets = []
    if self.waf:
      response = self.waf.list_ip_sets(Limit=100)
      if response and response.has_key('IPSets'):
        for ip_set in response['IPSets']:
          ip_sets.append(ip_set)

    self.ip_sets = ip_sets

    return ip_sets

  def _get_aws_waf_change_token(self):
    """
    Get a new AWS WAF change token (required for any changes)
    """
    response = self.waf.get_change_token()
    change_token = None
    if response and response.has_key('ChangeToken'):
      change_token = response['ChangeToken']
      self._log("New AWS WAF change token [{}]".format(change_token))

    return change_token