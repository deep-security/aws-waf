# make sure we add the current path structure to sys.path
# this is required to import local dependencies
import sys
import os
current_path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(current_path)

# import project files as required
import dsm
import translation
translation.Terms.read_terms_file()