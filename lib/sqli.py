# Standard libraries
import argparse
import inspect
import os
import re
import urllib2

# 3rd party libraries
import boto3
import boto3.session
import netaddr

# Project libraries
import core
import deepsecurity.manager

def run_script(args):
  # configure the command line args
  parser = core.get_arg_parser(prog='ds-to-aws-waf.py sqli', add_help=True)
  parser.add_argument('-l', '--list', action='store_true', required=False, help='List the available EC2 instances')
  parser.add_argument('--tag', action=core.StoreNameValuePairOnEquals, nargs="+", dest="tags", required=False, help='Specify the tags to filter the EC2 instances by')

  parser.add_argument('--create-match', action='store_true', required=False, dest="create_match", help='Create the SQLi match condition for use in various rules')
  
  script = Script(args[1:], parser)

  if script.args.list:
    # List the available EC2 instances and cross reference with Deep Security
    script.connect()
    script.get_ec2_instances()
    script.get_deep_security_info()
    recommendations = script.compare_ec2_to_deep_security()
    script.print_recommendations(recommendations)

  if script.args.create_match:
    script.connect()
    if script.args.dryrun:
      script._log("***********************************************************************", priority=True)
      script._log("* DRY RUN ENABLED. NO CHANGES WILL BE MADE", priority=True)
      script._log("***********************************************************************", priority=True)
    
    # create the recommend SQLi match condition
    script.create_match_condition()

  script.clean_up()

class Script(core.ScriptContext):
  def __init__(self, args, parser):
    core.ScriptContext.__init__(self, args, parser)
    #super(Script, self).__init__(args, parser)
    self.aws_credentials = None
    self.dsm = None
    self.ip_lists = []
    self.waf = None
    self.ec2 = None
    self.instances = {}
    self.tbuids = []
    self.patterns = []

    self.aws_credentials = self._get_aws_credentials()
    self.dsm = None
    self.waf = None

    self.cache_patterns()

  def connect(self):
    """
    Connect to Deep Security and AWS WAF
    """
    self.dsm = self._connect_to_deep_security()
    self.waf = self._connect_to_aws_waf()
    self.ec2 = self._connect_to_aws_ec2()

  def cache_patterns(self):
    """
    Cache the patterns for matching Deep Security rules for SQLi
    recommendations
    """
    CURRENT_FILE_DIR = os.path.dirname(os.path.abspath(inspect.stack()[0][1]))
    TBUIDS = os.path.join(CURRENT_FILE_DIR, 'sqli.tbuids')
    PATTERNS = os.path.join(CURRENT_FILE_DIR, 'sqli.patterns')

    if os.path.exists(TBUIDS):
      self._log("Caching TBUIDS for rule matching")
      with open(TBUIDS, 'r') as fh:
        for line in fh: self.tbuids.append(line.strip())

    if os.path.exists(PATTERNS):
      self._log("Caching patterns for rule matching")
      with open(PATTERNS, 'r') as fh:
        for line in fh: self.patterns.append(line.strip())

  def get_ec2_instances(self):
    """
    Get a list of EC2 instances from AWS
    """
    if self.ec2:
      # build any filters first
      filters = None
      if self.args.tags:
        filters = []
        for k, v in self.args.tags.items():
          filters.append({'Name':'tag:{}'.format(k), 'Values':['{}'.format(v)]})

        self._log("Applying {} filters to the request for EC2 instances".format(len(filters)))

    if filters:
      response = self.ec2.describe_instances(Filters=filters)
    else:
      response = self.ec2.describe_instances()

    if response and response.has_key('Reservations'):
      for reservation in response['Reservations']:
        if reservation.has_key('Instances'):
          for instance in reservation['Instances']:
            self.instances[instance['InstanceId']] = instance

  def get_deep_security_info(self):
    """
    Get all of the relevant information from Deep Security in order
    to build a smart rule set for AWS WAF
    """
    self._log("Requesting information from Deep Security about your deployment", priority=True)
    if self.dsm:
      self.dsm.get_all()
      self._log("Requesting rules from the Deep Security manager. This will take a few seconds...")
      self.dsm.get_all_rules()
      self._log("Requesting computers from the Deep Security manager. This will take a few seconds...")
      self.dsm.get_computers_with_details()
      self._log("Requested information from the Deep Security manager cached locally")

  def compare_ec2_to_deep_security(self):
    """
    Compare the list of EC2 instance returned from AWS vs
    the list of known instances in Deep Security
    """
    ds_instance_map = {}
    recommendations = {}
    if self.dsm and self.dsm.computers and self.instances:
      for computer_id, computer_details in self.dsm.computers.items():
        ds_instance_map[computer_details.cloud_object_instance_id] = computer_id

    for instance_id, instance_details in self.instances.items():
      if ds_instance_map.has_key(instance_id):
        self._log("Deep Security has instance {} in inventory".format(instance_id)) 
        recommendations[instance_id] = self.analyze_computer(ds_instance_map[instance_id])
      else:
        self._log("Deep Security does not have instance {} in inventory".format(instance_id)) 
        recommendations[instance_id] = None

    return recommendations

  def analyze_computer(self, ds_computer_id):
    """
    Analyze the specified computer to determine if it should be 
    protected by SQLi rules
    """
    self._log("Analyzing computer {}:{}".format(ds_computer_id, self.dsm.computers[ds_computer_id].hostname))
    recommendation = False
    computer = self.dsm.computers[ds_computer_id]
    if computer.policy_id:
      self._log("Computer is protected by Deep Security. Checking rules")
      sqli_recommendations = []
      for rule_type in [
        'integrity_monitoring_rules',
        'log_inspection_rules',
        'intrusion_prevention_rules'
        ]:
        if self.dsm.policies.has_key(computer.policy_id):
          rule_set = getattr(self.dsm.policies[computer.policy_id], rule_type)
          if rule_set: # policy has these type of rules applied
            for rule_id in getattr(self.dsm.policies[computer.policy_id], rule_type)[-1]:
              rule = self.dsm.rules[rule_type.replace('_rules', '')][rule_id]
              if 'tbuid' in dir(rule):
                if rule.tbuid in self.tbuids:
                  sqli_recommendations.append(rule)
                  continue

              if 'application_type_id' in dir(rule):
                if self.dsm.application_types.has_key(rule.application_type_id):
                  if self.dsm.application_types[rule.application_type_id].tbuid in self.tbuids:
                    sqli_recommendations.append(rule)
                    continue

              for pattern in self.patterns:
                for attr in [rule.name, rule.description]:
                  try:
                    m = re.search(pattern, attr)
                    if m:
                      sqli_recommendations.append(rule)
                  except Exception, err: pass # @TODO handle this gracefully
          else:
            self._log("Instance {} has no rules of type {} applied".format(computer.cloud_object_instance_id, rule_type))
        else:
          self._log("Policy {} is not available for analysis".format(computer.policy_id))

      if len(sqli_recommendations) > 1:
        recommendation = True if len(sqli_recommendations) > 0 else False
        self._log("Found {} rules indicating this instance should be protected by an SQLi rule set".format(len(sqli_recommendations)))
    else:
      self._log("Deep Security is aware of the instance but is not protecting it")
      recommendation = None

    return recommendation

  def print_recommendations(self, recommendations):
    """
    Print the recommendations for each instance
    """
    self._log("************************************************************************", priority=True)
    self._log("Completed recommendation phase", priority=True)
    self._log("   Instance\tRecommendation", priority=True)
    for instance_id, recommendation in recommendations.items():
      print "   {}\t{}".format(instance_id, recommendation, priority=True)

    self._log("************************************************************************", priority=True)      

  def create_match_condition(self):
    """
    Create the recommend SQLi match condition

    Reference for SQLi match sets is available at http://docs.aws.amazon.com/waf/latest/developerguide/web-acl-sql-conditions.html
    """
    MATCH_SET_NAME = "Deep Security SQLi Guidance"

    # does the match set already exist?
    exists = False
    response = self.waf.list_sql_injection_match_sets(Limit=100)
    if response and response.has_key('SqlInjectionMatchSets'):
      for match_set in response['SqlInjectionMatchSets']:
        if match_set['Name'] == MATCH_SET_NAME:
          exists = True
          break

    if exists:
      self._log("Desired SQLi match set already exists. No action needed")
    else:
      self._log("Attempting to create a new SQLi match set; {}".format(MATCH_SET_NAME))
      sqli_match_set_updates = [
        { 'Action': 'INSERT', 'SqlInjectionMatchTuple': { 'FieldToMatch': { 'Type': 'URI', 'Data': 'string' }, 'TextTransformation': 'URL_DECODE' }},
        { 'Action': 'INSERT', 'SqlInjectionMatchTuple': { 'FieldToMatch': { 'Type': 'QUERY_STRING', 'Data': 'string' }, 'TextTransformation': 'URL_DECODE' }},
        { 'Action': 'INSERT', 'SqlInjectionMatchTuple': { 'FieldToMatch': { 'Type': 'QUERY_STRING', 'Data': 'string' }, 'TextTransformation': 'HTML_ENTITY_DECODE' }},
        { 'Action': 'INSERT', 'SqlInjectionMatchTuple': { 'FieldToMatch': { 'Type': 'QUERY_STRING', 'Data': 'string' }, 'TextTransformation': 'LOWERCASE' }},
        { 'Action': 'INSERT', 'SqlInjectionMatchTuple': { 'FieldToMatch': { 'Type': 'BODY', 'Data': 'string' }, 'TextTransformation': 'URL_DECODE' }},
        { 'Action': 'INSERT', 'SqlInjectionMatchTuple': { 'FieldToMatch': { 'Type': 'BODY', 'Data': 'string' }, 'TextTransformation': 'HTML_ENTITY_DECODE' }},
        { 'Action': 'INSERT', 'SqlInjectionMatchTuple': { 'FieldToMatch': { 'Type': 'BODY', 'Data': 'string' }, 'TextTransformation': 'LOWERCASE' }},
        ]
      if not self.args.dryrun:
        # get a change token
        change_token = self._get_aws_waf_change_token()
        if change_token:
          # create the match set
          match_set_id = None
          try:
            response = self.waf.create_sql_injection_match_set(
              Name=MATCH_SET_NAME,
              ChangeToken=change_token
              )
            self._log("Created a new SQLi match set: {}".format(MATCH_SET_NAME))

            if response and response.has_key('SqlInjectionMatchSet') and response['SqlInjectionMatchSet'].has_key('SqlInjectionMatchSetId'):
              match_set_id = response['SqlInjectionMatchSet']['SqlInjectionMatchSetId']

          except Exception, err:
            self._log("Could not create a new SQLi match set", err=err)
            return

          if match_set_id:
            # get another change token
            change_token = self._get_aws_waf_change_token()
            if change_token:
              # update the match set
              try:
                response = self.waf.update_sql_injection_match_set(
                  SqlInjectionMatchSetId=match_set_id,
                  ChangeToken=change_token,
                  Updates=sqli_match_set_updates
                  )
                self._log("Updated SQLi match set; {}".format(MATCH_SET_NAME), priority=True)
              except Exception, err:
                self._log("Unable to update SQLi match set", err=err)
      else:
        self._log("Would request an AWS WAF change token to create a new SQLi match set", priority=True)
        self._log("   SQLi match set will contain;", priority=True)
        for update in sqli_match_set_updates:
          self._log("      {}".format(update), priority=True)