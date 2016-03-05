# Standard libraries
import argparse
import os
import urllib2

def get_arg_parser(prog='ds-to-aws-waf.py', description=None):
  """
  Create a standardized argument parser
  """
  if not description:
    description = """
    Create and update AWS WAF WACL rules based on information from a Deep Security installation
"""

  parser = argparse.ArgumentParser(prog=prog, description=description)

  # Deep Security arguments
  parser.add_argument('-d', '--dsm', action='store', default='app.deepsecurity.trendmicro.com', required=False, help='The address of the Deep Security Manager. Defaults to Deep Security as a Service')
  parser.add_argument('--dsm-port', action='store', default='4119', dest='dsm_port', required=False, help='The address of the Deep Security Manager. Defaults to an AWS Marketplace/software install (:4119). Automatically configured for Deep Security as a Service')
  parser.add_argument('-u', '--dsm-username', action='store', required=True, help='The Deep Security username to access the IP Lists with. Should only have read-only rights to IP lists and API access')
  parser.add_argument('-p', '--dsm-password', action='store', required=True, help='The password for the specified Deep Security username. Should only have read-only rights to IP lists and API access')
  parser.add_argument('-t', '--dsm-tenant', action='store', required=False, default=None, help='The name of the Deep Security tenant/account')

  # general structure arguments
  parser.add_argument('--ignore-ssl-validation', action='store_true', dest='ignore_ssl_validation', required=False, help='Ignore SSL certification validation. Be careful when you use this as it disables a recommended security check. Required for Deep Security Managers using a self-signed SSL certificate')
  parser.add_argument('--dryrun', action='store_true', required=False, help='Do a dry run of the command. This will not make any changes to your AWS WAF service')
  parser.add_argument('--verbose', action='store_true', required=False, help='Enabled verbose output for the script. Useful for debugging')

  return parser

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
      self._log("""***********************************************************************
* IGNORING SSL CERTIFICATE VALIDATION
* ===================================
* You have requested to ignore SSL certificate validation. This is a less secure method 
* of connecting to a Deep Security Manager (DSM). Please ensure that you have other 
* mitigations and security controls in place (like restricting IP space that can access 
* the DSM, implementing least privilege for the Deep Security user/role accessing the 
* API, etc).
*
* During script execution, you'll see a number of "InsecureRequestWarning" messages. 
* These are to be expected when operating without validation. 
***********************************************************************""", priority=True)
    try:
      dsm_port = self.args.dsm_port if not self.args.dsm === 'app.deepsecurity.trendmicro.com' else 443
      dsm = deepsecurity.manager.Manager(dsm_hostname=self.args.dsm, dsm_port=dsm_port, username=self.args.username, password=self.args.password, tenant=self.args.tenant, ignore_ssl_validation=self.args.ignore_ssl_validation) 
      self._log("Connected to the Deep Security Manager at {}".format(self.args.dsm))
    except Exception, err: pass # @TODO handle this exception gracefully

    if not dsm.session_id_rest and not dsm.session_id_soap:
      self._log("Unable to connect to the Deep Security Manager. Please check your settings")
      if not self.args.ignore_ssl_validation:
        self._log("You did not ask to ignore SSL certification validation. This is a common error when connect to a Deep Security Manager that was installed via software or the AWS Marketplace. Please set the flag (--ignore-ssl-validation), check your other settings, and try again")

    return dsm 

  def _connect_to_aws_waf(self):
    waf = None
    try:
      aws = boto3.session.Session(aws_access_key_id=self.aws_credentials['aws_access_key_id'], aws_secret_access_key=self.aws_credentials['aws_secret_access_key'])
      waf = aws.client('waf') 
      self._log("Connected to AWS WAF")
    except Exception, err: 
      # @TODO handle this exception gracefully
      try:
        waf = boto3.client('waf')
        self._log("Connected to AWS WAF")
      except Exception, err: pass # @TODO handle this exception gracefully  

    return waf

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
    response = self.waf.get_change_token()
    change_token = None
    if response and response.has_key('ChangeToken'):
      change_token = response['ChangeToken']
      self._log("New AWS WAF change token [{}]".format(change_token))

    return change_token