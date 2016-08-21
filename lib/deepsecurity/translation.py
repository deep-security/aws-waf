# standard library
import os
import re

# 3rd party libraries

# project libraries

class Terms(object):
  # these dict are initialized in the module's __init__.py
  api_to_new = {}
  new_to_api = {}

  @classmethod
  def read_terms_file(self):
    current_directory_path = os.path.dirname(os.path.realpath(__file__))
    terms_file_path = os.path.join(current_directory_path, "terms.txt")

    if os.path.exists(terms_file_path):
        # read each API term and setup the necessary lookups
        with open(terms_file_path, 'r') as fh:
            for line in fh:
                term = line.strip()
                term_lower = term.lower()
                term_new = re.sub('([A-Z]+)', r'_\1', term).lower().lstrip('_')
                
                # catch the term_new exceptions
                if 'dpi' in term_new:
                    term_new = re.sub('dpi', '_intrusion_prevention_', term_new, re.IGNORECASE)
                if 'host' in term_new:
                    term_new = re.sub('host', '_computer_', term_new, re.IGNORECASE)
                if 'securityprofile' in term_new:
                    term_new = re.sub('securityprofile', '_policy_', term_new, re.IGNORECASE)
                if 'integrity' in term_new:
                    term_new = re.sub('((?=integrity(?!_monitoring)))', '_integrity_monitoring_', term_new, re.IGNORECASE)
                    term_new = term_new.replace('integrity_monitoring_integrity', 'integrity_monitoring')
                
                term_new = term_new.replace('__', '_').strip('_')

                self.api_to_new[term_lower] = term_new
                self.new_to_api[term_new] = term
  
  @classmethod
  def get_reverse(self, term_new):
    """
    For the given new term, return the original API term
    """
    result = term_new
    if self.new_to_api.has_key(term_new):
        result = self.new_to_api[term_new]

    return result

  @classmethod
  def get(self, term):
    """
    Return the translation of the specified API term
    """
    if self.api_to_new.has_key(term.lower()):
      return self.api_to_new[term.lower()]
    else:
      return term