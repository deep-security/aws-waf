#! /usr/bin/env python

# Standard libraries
import argparse
import os
import urllib2
import sys

# 3rd party libraries
import boto3
import boto3.session
import netaddr

# project libraries
import lib.iplists

def parse_args(str_to_parse=None):
  """
  Parse the command line args
  """
  cmd = ""
  if len(sys.argv) > 1:
    cmd = sys.argv[1]

  return cmd

class ScriptContext():
  """
  Context for IP List to IP Set script.

  Using an object makes is easy to avoid any globals and clarifies 
  the intention of the script
  """
  def __init__(self, command_to_run):
    self.command_to_run = command_to_run
    self.available_commands = {
        'iplist': 
          { 
            'help': 'Push a Deep Security IP list to an AWS WAF IP Set',
            'cmd': self.update_user,
          },
        'sqli': 
          {
            'help': 'Determine which instances protected by Deep Security should also be protected by AWS WAF SQLi rules',
            'cmd': self.update_user,
          },
      }

    if not self.command_to_run in self.available_commands.keys():
      self.print_help()
    else:
      # run a specific command
      self.available_commands[self.command_to_run]['cmd'](sys.argv[1:])

  def update_user(self, msg):
    """
    Update user via stdout
    """
    print(msg)

  def print_help(self):
    """
    Print the command line syntax available to the user
    """
    self.update_user("usage: ds-to-aws-waf [COMMAND]\n   For more help on a specific command, type ds-to-aws-waf [COMMAND] --help\n\n   Available commands:\n")
    for cmd, data in self.available_commands.items():
      self.update_user("   {}\n      > {}".format(cmd, data['help']))
    self.update_user("")

def main():
  """
  Run the script from the command line
  """
  context = ScriptContext(parse_args())


if __name__ == '__main__': main()