# Standard libraries
import argparse
import os
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
  parser = core.get_arg_parser(prog='ds-to-aws-waf.py sqli')
  parser.add_argument('-l', '--list', action='store_true', required=False, help='List the available EC2 instances')
  parser.add_argument('--tag', action=core.StoreNameValuePairOnEquals, nargs="+", dest="tags", required=False, help='Specify the tags to filter the EC2 instances by')
  
  script = Script(args[1:], parser)
  
  if script.args.list:
    # List the available EC2 instances and cross reference with Deep Security
    print "1"
    script.connect()
    print "2"
    script.get_ec2_instances()
    print "3"
    script.get_deep_security_info()
    print "4"
    script.compare_ec2_to_deep_security()
    print "5"
    #script.print_lists()

  a ="""
  elif script.args.ip_list:
    script.connect()
    if script.args.dryrun:
      script._log("***********************************************************************", priority=True)
      script._log("* DRY RUN ENABLED. NO CHANGES WILL BE MADE", priority=True)
      script._log("***********************************************************************", priority=True)
    # get the specified Deep Security IP Lists (already cached)
    ip_list = script.get_ds_list(script.args.ip_list)
    # create the IP Set
    if ip_list:
      script.create_ip_set(ip_list)

  script.clean_up()
  """
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

    self.aws_credentials = self._get_aws_credentials()
    self.dsm = None #self._connect_to_deep_security()
    self.waf = None #self._connect_to_aws_waf()
    self.ip_lists = None #self._get_available_ds_lists()

  def connect(self):
    """
    Connect to Deep Security and AWS WAF
    """
    self.dsm = self._connect_to_deep_security()
    self.waf = self._connect_to_aws_waf()
    self.ec2 = self._connect_to_aws_ec2()

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
    if self.dsm and self.dsm.computers and self.instances:
      for computer_id, computer_details in self.dsm.computers.items():
        ds_instance_map[computer_details.cloud_object_instance_id] = computer_id

    for instance_id, instance_details in self.instances.items():
      if ds_instance_map.has_key(instance_id):
        self._log("Deep Security has instance {} in inventory".format(instance_id)) 
        self.analyze_computer(ds_instance_map[instance_id])
      else:
        self._log("Deep Security does not have instance {} in inventory".format(instance_id)) 

  def analyze_computer(self, ds_computer_id):
    """
    Analyze the specified computer to determine if it should be 
    protected by SQLi rules
    """
    self._log("Analyzing computer {}:{}".format(ds_computer_id, self.dsm.computers[ds_computer_id].hostname))
    computer = self.dsm.computers[ds_computer_id]
    if computer.policy_id:
      self._log("Computer is protected by Deep Security. Checking rules")
      for rule_type in [
        'integrity_monitoring_rules',
        'log_inspection_rules',
        'intrusion_prevention_rules'
        ]:
        for rule_id in getattr(self.dsm.policies[computer.policy_id], rule_type)[-1]:
          rule = self.dsm.rules[rule_type.replace('_rules', '')][rule_id]
          print "{}:{}".format(rule_type, rule.name.encode('ascii', 'ignore'))
    else:
      self._log("Computer is NOT protected by Deep Security")