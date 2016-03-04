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
  print("Running iplists with args: {}".format(" ".join(args)))
  parser = core.get_arg_parser(prog='ds-to-aws-waf.py iplists')
  script = Script(args, parser)

class Script(core.ScriptContext):
  pass