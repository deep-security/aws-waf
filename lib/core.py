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

  def update_user(self, msg, err=None):
    """
    Update user via stdout
    """
    if err:
      print("{}. Threw an exception:\n{}".format(msg, err))
    else:
      print(msg)

  def print_help(self):
    """
    Print the command line syntax available to the user
    """
    self.parser.print_help()   