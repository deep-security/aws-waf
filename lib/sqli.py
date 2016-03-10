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
  parser.add_argument('--map-to-wacl', action='store_true', required=False, dest="map_to_wacl", help='Attempt to map each instance to an AWS WAF WACL')
  parser.add_argument('--create-rule', action='store_true', required=False, dest="create_rule", help='Create the SQLi rule for instances that can be mapped to an AWS WAF WACL. Used in conjunction with -l/--list')
  
  script = Script(args[1:], parser)

  if script.args.list:
    # List the available EC2 instances and cross reference with Deep Security
    script.connect()
    script.get_ec2_instances()
    script.get_deep_security_info()
    script.get_waf_support_structures()
    script.map_instances_to_wacls()
    recommendations = script.compare_ec2_to_deep_security()
    script.print_recommendations(recommendations)
    if script.args.create_rule:
      if script.args.dryrun:
        script._log("***********************************************************************", priority=True)
        script._log("* DRY RUN ENABLED. NO CHANGES WILL BE MADE", priority=True)
        script._log("***********************************************************************", priority=True)
      
      # create the rule and update the WACLs 
      # --dryrun is handled directly in the functions
      rule_created = False
      for instance_id, wacl_id in script.instances_to_wacls.items():
        if not rule_created:
          script.create_wacl_rule() # idempotent
          rule_created = True

        script.update_wacl(wacl_id)

  if script.args.create_match:
    script.connect()
    if script.args.dryrun:
      script._log("***********************************************************************", priority=True)
      script._log("* DRY RUN ENABLED. NO CHANGES WILL BE MADE", priority=True)
      script._log("***********************************************************************", priority=True)
    
    # create the recommend SQLi match condition
    script.create_match_condition()

  if script.args.map_to_wacl:
    script.connect()
    script.get_waf_support_structures()
    script.map_instances_to_wacls()
    script.print_instances_to_wacls_map()

  if script.args.create_rule and not script.args.list:
    script._log("The --create-rule switch must be used with the -l/--list switch", priority=True)

  script.clean_up()

class Script(core.ScriptContext):
  def __init__(self, args, parser):
    core.ScriptContext.__init__(self, args, parser)
    #super(Script, self).__init__(args, parser)
    self.aws_credentials = None
    self.dsm = None
    self.waf = None
    self.ec2 = None
    self.elb = None
    self.cloudfront = None

    self.MATCH_SET_NAME = "Deep Security SQLi Guidance"
    self.RULE_NAME = "Deep Security Block SQLi"
    
    self.ip_lists = []
    self.instances = {}
    self.elbs = {}
    self.cloudfront_distributions = {}
    self.wacls = {}
    self.instances_to_wacls = {}
    self.tbuids = []
    self.patterns = []

    self.aws_credentials = self._get_aws_credentials()

    self.cache_patterns()

  def connect(self):
    """
    Connect to Deep Security and AWS WAF
    """
    self.dsm = self._connect_to_deep_security()
    self.waf = self._connect_to_aws_waf()
    self.ec2 = self._connect_to_aws_ec2()
    self.elb = self._connect_to_aws_elb()
    self.cloudfront = self._connect_to_aws_cloudfront()

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
    filters = None
    if self.ec2:
      # build any filters first
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

  def get_elbs(self):
    """
    Get all of the ELBs active in the current region
    """
    if self.elb:
      response = self.elb.describe_load_balancers(PageSize=400)
      if response and response.has_key('LoadBalancerDescriptions'):
        for elb in response['LoadBalancerDescriptions']:
          self.elbs[elb['LoadBalancerName']] = elb

  def get_cloudfront_distributions(self):
    """
    Get all of the CloudFront distributions
    """
    if self.cloudfront:
      response = self.cloudfront.list_distributions(MaxItems='100')
      if response and response.has_key('DistributionList') and response['DistributionList'].has_key('Items'):
        for distribution in response['DistributionList']['Items']:
          self.cloudfront_distributions[distribution['Id']] = distribution

  def get_wacls(self):
    """
    Get all of the AWS WAF WACLs
    """
    if self.waf:
      response = self.waf.list_web_acls(Limit=100)
      if response and response.has_key('WebACLs'):
        for wacl in response['WebACLs']:
          self.wacls[wacl['WebACLId']] = wacl

  def get_waf_support_structures(self):
    """
    Get all of the AWS object information for supporting
    AWS WAF WACLs
    """
    self.get_ec2_instances()
    self.get_elbs()
    self.get_cloudfront_distributions()
    self.get_wacls()

  def map_instances_to_wacls(self):
    """
    For each EC2 instance, attempt to map it to an AWS WAF WACL
    """
    self._log("Attempting to map each EC2 instance to an AWS WAF WACL")
    for instance_id, instance in self.instances.items():
      self._log("Mapping instance [{}]".format(instance_id))
      # is this instance connected to an ELB?
      for elb_id, elb in self.elbs.items():
        for registered_instance in elb['Instances']:
          if registered_instance['InstanceId'] == instance_id:
            self._log("Instance [{}] is registered to ELB [{}]".format(instance_id, elb_id))
            registered_origin_id_prefix = 'elb-{}'.format(elb_id.lower())
            for distro_id, distro in self.cloudfront_distributions.items():
              for origin in distro['Origins']['Items']:
                if origin['Id'].lower().startswith(registered_origin_id_prefix):
                  self._log('ELB [{}] is a registered origin for CloudFront Distribution [{}]'.format(elb_id, distro_id))
                  if self.wacls.has_key(distro['WebACLId']):
                    self._log('CloudFront Distribution [{}] is protected by WebACL [{}]'.format(distro_id, distro['WebACLId']))
                    self.instances_to_wacls[instance_id] = distro['WebACLId']

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

  def does_rule_match_sqli(self, rule):
    """
    Determine if a rule matches the defined parameters for an 
    SQLi recommendation
    """
    sqli_recommended = False
    if 'tbuid' in dir(rule):
      sqli_recommended = True

    if 'application_type_id' in dir(rule):
      if self.dsm.application_types.has_key(rule.application_type_id):
        if self.dsm.application_types[rule.application_type_id].tbuid in self.tbuids:
          sqli_recommended = True

    for pattern in self.patterns:
      if 'name' in dir(rule) and 'description' in dir(rule):
        for attr in [rule.name, rule.description]:
          try:
            m = re.search(pattern, attr)
            if m:
              sqli_recommended = True
          except Exception, err: pass # @TODO handle this gracefully

    return sqli_recommended

  def analyze_computer(self, ds_computer_id):
    """
    Analyze the specified computer to determine if it should be 
    protected by SQLi rules
    """
    self._log("Analyzing computer {}:{}".format(ds_computer_id, self.dsm.computers[ds_computer_id].hostname))
    recommendation = False
    self.dsm.get_recommended_rules_for_computer(ds_computer_id)
    computer = self.dsm.computers[ds_computer_id]
    sqli_recommendations = []
      
    # check at the policy level
    if computer.policy_id:
      self._log("Computer is protected by Deep Security. Checking rules")
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
              if self.does_rule_match_sqli(rule): sqli_recommendations.append(rule)
          else:
            self._log("Instance {} has no rules of type {} applied".format(computer.cloud_object_instance_id, rule_type))
        else:
          self._log("Policy {} is not available for analysis".format(computer.policy_id))
    else:
      self._log("Deep Security is aware of the instance but is not protecting it with a policy")
      recommendation = None

    # now check for any recommendations to the computer
    for rule_type, rules in computer.recommended_rules.items():
      self._log("Checking for recommended {} rules".format(rule_type))
      for rule_id, rule in rules.items():
        if self.does_rule_match_sqli(rule): sqli_recommendations.append(rule)
      
      for application_type_id, application_type in computer.application_types.items():
        if application_type.tbuid in self.tbuids:
          sqli_recommendations.append(application_type)

    if len(sqli_recommendations) > 1:
      recommendation = True if len(sqli_recommendations) > 0 else False
      self._log("Found {} rules indicating this instance should be protected by an SQLi rule set".format(len(sqli_recommendations)))

    return recommendation

  def print_recommendations(self, recommendations):
    """
    Print the recommendations for each instance
    """
    self._log("************************************************************************", priority=True)
    self._log("Completed recommendation phase", priority=True)
    self._log("   Instance\tRecommendation\tSuggested WACL", priority=True)
    for instance_id, recommendation in recommendations.items():
      suggested_wacl = self.instances_to_wacls[instance_id] if self.instances_to_wacls.has_key(instance_id) else ''
      self._log("   {}\t{}\t{}".format(instance_id, recommendation, suggested_wacl), priority=True)

    self._log("************************************************************************", priority=True)      

  def print_instances_to_wacls_map(self):
    """
    Print the instances to WACLs map
    """
    self._log("************************************************************************", priority=True)
    self._log("Discovered mappings of EC2 instance to WACL", priority=True)
    self._log("   Instance\tSuggested WACL", priority=True)
    for instance_id, instance in self.instances.items():
      wacl = self.instances_to_wacls[instance_id] if self.instances_to_wacls.has_key(instance_id) else "---"
      self._log("   {}\t{}".format(instance_id, wacl), priority=True)
    self._log("************************************************************************", priority=True)      

  def create_match_condition(self):
    """
    Create the recommend SQLi match condition

    Reference for SQLi match sets is available at http://docs.aws.amazon.com/waf/latest/developerguide/web-acl-sql-conditions.html
    """
    # does the match set already exist?
    exists = False
    response = self.waf.list_sql_injection_match_sets(Limit=100)
    if response and response.has_key('SqlInjectionMatchSets'):
      for match_set in response['SqlInjectionMatchSets']:
        if match_set['Name'] == self.MATCH_SET_NAME:
          exists = True
          break

    if exists:
      self._log("Desired SQLi match set already exists. No action needed")
    else:
      self._log("Attempting to create a new SQLi match set; {}".format(self.MATCH_SET_NAME))
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
              Name=self.MATCH_SET_NAME,
              ChangeToken=change_token
              )
            self._log("Created a new SQLi match set: {}".format(self.MATCH_SET_NAME))

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
                self._log("Updated SQLi match set; {}".format(self.MATCH_SET_NAME), priority=True)
              except Exception, err:
                self._log("Unable to update SQLi match set", err=err)
      else:
        self._log("Would request an AWS WAF change token to create a new SQLi match set", priority=True)
        self._log("   SQLi match set will contain;", priority=True)
        for update in sqli_match_set_updates:
          self._log("      {}".format(update), priority=True)
<<<<<<< HEAD

  def get_match_condition(self):
    """
    Get the ID of the Deep Security SQLi match condition
    """
    result = None

    match_set_id = None
    response = self.waf.list_sql_injection_match_sets(Limit=100)
    if response and response.has_key('SqlInjectionMatchSets'):
      for match_set in response['SqlInjectionMatchSets']:
        if match_set['Name'] == self.MATCH_SET_NAME:
          match_set_id = match_set['SqlInjectionMatchSetId']

    if match_set_id:
      try:
        response = self.waf.get_sql_injection_match_set(SqlInjectionMatchSetId=match_set_id)
        if response and response.has_key('SqlInjectionMatchSet'):
          result = response['SqlInjectionMatchSet']['SqlInjectionMatchSetId']
      except Exception, err: pass

    return result

  def get_rule(self):
    """
    Get the ID of the Deep Security SQLi rule
    """
    result = None

    rule_id = None
    response = self.waf.list_rules(Limit=100)
    if response and response.has_key('Rules'):
      for rule in response['Rules']:
        if rule['Name'] == self.RULE_NAME:
          rule_id = rule['RuleId']

    if rule_id:
      try:
        response = self.waf.get_rule(RuleId=rule_id)
        if response and response.has_key('Rule'):
          result = response['Rule']['RuleId']
      except Exception, err: pass

    return result

  def create_wacl_rule(self):
    """
    Create the SQLi rule for the specified WACL
    """
    # make sure the SQLi match condition exists
    self.create_match_condition() # self.args.dryrun is handled in the function
    match_set_id = self.get_match_condition()

    sqli_rule_updates = [
        { 'Action': 'INSERT', 'Predicate': {
              'Negated': True,
              'Type': 'SqlInjectionMatch',
              'DataId': match_set_id,
            }
          }
      ]

    if match_set_id:
      if not self.args.dryrun and not self.get_rule():
        # get a change token
        change_token = self._get_aws_waf_change_token()
        if change_token:
          response = self.waf.create_rule(
              Name=self.RULE_NAME,
              MetricName='DsSqliBlocks',
              ChangeToken=change_token
            )

          rule_id = None
          if response and response.has_key('Rule'):
            rule_id = response['Rule']['RuleId']

          if rule_id:
            # get a change token
            change_token = self._get_aws_waf_change_token()
            if change_token:
              response = self.waf.update_rule(
                  RuleId=rule_id,
                  ChangeToken=change_token, 
                  Updates=sqli_rule_updates,
                )

              if response and response.has_key('ChangeToken'):
                self._log("Successfully created rule []".format(self.RULE_NAME), priority=True)
                self._log("   With predicates: {}".format(sqli_rule_updates))
              else:
                self._log("Failed to create rule []".format(self.RULE_NAME))
      else:
        self._log("Would create rule []".format(self.RULE_NAME))
        self._log("   With predicates: {}".format(sqli_rule_updates))

  def update_wacl(self, wacl_id):
    """
    Update the specified WACL with the Deep Security SQLi rule
    """

    wacl_updates = [
        { 
          'Action': 'INSERT', 'ActivatedRule': {
              'Priority': 100,
              'RuleId': self.get_rule(),
              'Action': { 'Type': 'BLOCK' },
            }
          }
      ]

    if not self.args.dryrun:
      if self.get_rule(): # rule exists, continue
        # get a change token
        change_token = self._get_aws_waf_change_token()

        if change_token:
          response = self.waf.update_web_acl(
              WebACLId=wacl_id,
              ChangeToken=change_token,
              Updates=wacl_updates,
              DefaultAction={ 'Type': 'BLOCK' },
            )
          if response and response.has_key('ChangeToken'):
            self._log("Successfully updated WACL [{}]".format(wacl_id), priority=True)
            self._log("   With updates: {}".format(wacl_updates))
          else:
            self._log("Unable to update WACL [{}]".format(wacl_id), priority=True)
      else:
        self._log("Would have updated WACL [{}]".format(wacl_id), priority=True)
        self._log("   With updates: {}".format(wacl_updates))
=======
>>>>>>> 68e192bd626611b1bd0d74fbd0f41df46cf5781f
