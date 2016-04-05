# standard library
import collections
import json
import logging
import re
import ssl
import urllib
import urllib2

# 3rd party libraries
import libs.xmltodict as xmltodict

# project libraries
import translation

class CoreApi(object):
  def __init__(self):
    self.API_TYPE_REST = 'REST'
    self.API_TYPE_SOAP = 'SOAP'
    self._rest_api_endpoint = ''
    self._soap_api_endpoint = ''
    self._sessions = { self.API_TYPE_REST: None, self.API_TYPE_SOAP: None }
    self.ignore_ssl_validation = False
    self._log_at_level = logging.WARNING
    self.logger = self._set_logging()

  # *******************************************************************
  # properties
  # *******************************************************************
  @property
  def log_at_level(self): return self._log_at_level
  
  @log_at_level.setter
  def log_at_level(self, value):
    """
    Make sure logging is always set at a valid level
    """
    if value in [
      logging.CRITICAL,
      logging.DEBUG,
      logging.ERROR,
      logging.FATAL,
      logging.INFO,
      logging.WARNING,
      ]:
      self._log_at_level = value
      self._set_logging()
    else:
      if not self._log_at_level:
        self._log_at_level = logging.WARNING
        self._set_logging()

  # *******************************************************************
  # methods
  # *******************************************************************
  def _set_logging(self):
    """
    Setup the overall logging environment
    """
    # Based on tips from http://www.blog.pythonlibrary.org/2012/08/02/python-101-an-intro-to-logging/
    logging.basicConfig(level=self.log_at_level)

    # setup module logging
    logger = logging.getLogger("DeepSecurity.API")
    logger.setLevel(self.log_at_level)

    # reset any existing handlers
    logging.root.handlers = [] # @TODO evaluate impact to other modules
    logger.handlers = []

    # add the desired handler
    formatter = logging.Formatter('[%(asctime)s]\t%(message)s', '%Y-%m-%d %H:%M:%S')
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger

  def _get_request_format(self, api=None, call=None):
    if not api: api = self.API_TYPE_SOAP
    return {
      'api': api,
      'call': call,
      'query': None,
      'data': None,
    }

  def _request(self, request, auth_required=True):
    """
    Make an HTTP(S) request to an API endpoint based on what's specified in the 
    request object passed

    ## Input

    Required request keys:
      api
        Either REST or SOAP

      call
        Name of the SOAP method or relative path of the REST URL 

    Optional keys:
      query
        Contents of the query string passed as a dict

      data
        Data to post. For SOAP API calls this will be the SOAP envelope. For
        REST API calls this will be a dict converted to JSON automatically 
        by this method

    ## Output

    Returns a dict:
      status
        Number HTTP status code returned by the response, if any

      raw
        The raw contents of the response, if any

      data
        A python dict representing the data contained in the response, if any
    """
    for required_key in [
      'api',
      'call'
      ]:
      if not request.has_key(required_key) and request[required_key]:
        self.log("All requests are required to have a key [{}] with a value".format(required_key), level='critical')
        return None

    url = None
    if request['api'] == self.API_TYPE_REST:
      url = "{}/{}".format(self._rest_api_endpoint, request['call'].lstrip('/'))
    else:
      url = self._soap_api_endpoint

    self.log("Making a request to {}".format(url), level='debug')

    # add the authentication parameters
    if auth_required:
      if request['api'] == self.API_TYPE_REST:
        # sID is a query string
        if not request['query']: request['query'] = {}
        request['query']['sID'] = self._sessions[self.API_TYPE_REST]
      elif request['api'] == self.API_TYPE_SOAP:
        # sID is part of the data
        if not request['data']: request['data'] = {}
        request['data']['sID'] = self._sessions[self.API_TYPE_SOAP]

    # remove any blank request keys
    for k, v in request.items():
      if not v: request[k] = None

    # prep the query string
    if request.has_key('query') and request['query']:
      # get with query string
      qs = {}
      for k, v in request['query'].items(): # strip out null entries
        if v: qs[k] = v

      url += '?%s' % urllib.urlencode(qs)
      self.log("Added query string. Full URL is now {}".format(url), level='debug')

    self.log("URL to request is: {}".format(url))

    # Prep the SSL context
    ssl_context = ssl.create_default_context()
    if self.ignore_ssl_validation:
      ssl_context.check_hostname = False
      ssl_context.verify_mode = ssl.CERT_NONE
      self.log("SSL certificate validation has been disabled for this call", level='warning')

    # Prep the URL opener
    url_opener = urllib2.build_opener(urllib2.HTTPSHandler(context=ssl_context))
  
    # Prep the request
    request_type = 'GET'
    headers = {
      'Accept': 'application/json,text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*',
      'Content-Type': 'application/json',
      }

    # authentication calls don't accept the Accept header
    if request['call'].startswith('authentication'): del(headers['Accept'])
    if request['api'] == self.API_TYPE_REST and request['call'] in [
      'apiVersion',
      'status/manager/ping'
      ]:
      headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*',
        'Content-Type': 'text/plain',
        }

    if request['api'] == self.API_TYPE_SOAP:
      # always a POST
      headers = {
        'SOAPAction': '',
        'content-type': 'application/soap+xml'
        }
      data = self._prep_data_for_soap(request['call'], request['data'])
      url_request = urllib2.Request(url, data=data, headers=headers)
      request_type = 'POST'
      self.log("Making a SOAP request with headers {}".format(headers), level='debug')
      self.log("   and data {}".format(data), level='debug')
    elif request['call'] == 'authentication/logout':
      url_request = urllib2.Request(url, headers=headers)
      setattr(url_request, 'get_method', lambda: 'DELETE') # make this request use the DELETE HTTP verb
      request_type = 'DELETE'
      self.log("Making a REST DELETE request with headers {}".format(headers), level='debug')
    elif request.has_key('data') and request['data']:
      # POST
      url_request = urllib2.Request(url, data=json.dumps(request['data']), headers=headers)
      request_type = 'POST'
      self.log("Making a REST POST request with headers {}".format(headers), level='debug')
      self.log("    and data {}".format(request['data']), level='debug')
    else:
      # GET
      url_request = urllib2.Request(url, headers=headers)
      self.log("Making a REST GET request with headers {}".format(headers), level='debug')

    # Make the request
    response = None
    try:
      response = url_opener.open(url_request)
    except Exception, url_err:
      self.log("Failed to make {} {} call [{}]".format(request['api'].upper(), request_type, request['call'].lstrip('/')), err=url_err)

    # Convert the request from JSON
    result = {
      'status': response.getcode() if response else None,
      'raw': response.read() if response else None,
      'data': None
    }
    bytes_of_data = len(result['raw']) if result['raw'] else 0
    self.log("Call returned HTTP status {} and {} bytes of data".format(result['status'], bytes_of_data), level='debug')

    if response:
      if request['api'] == self.API_TYPE_SOAP:
        # XML response
        try:
          if result['raw']:
            full_data = xmltodict.parse(result['raw'])
            if full_data.has_key('soapenv:Envelope') and full_data['soapenv:Envelope'].has_key('soapenv:Body'):
              result['data'] = full_data['soapenv:Envelope']['soapenv:Body']
              if result['data'].has_key('{}Response'.format(request['call'])):
                if result['data']['{}Response'.format(request['call'])].has_key('{}Return'.format(request['call'])):
                  result['data'] = result['data']['{}Response'.format(request['call'])]['{}Return'.format(request['call'])]
                else:
                  result['data'] = result['data']['{}Response'.format(request['call'])]
            else:
              result['data'] = full_data
        except Exception, xmltodict_err:
          self.log("Could not convert response from call {}".format(request['call']), err=xmltodict_err)
      else:
        # JSON response
        try:
          if result['raw']:
            result['data'] = json.loads(result['raw'])
        except Exception, json_err:
          # report the exception as 'info' because it's not fatal and the data is 
          # still captured in result['raw']
          self.log("Could not convert response from call {} to JSON. Threw exception:\n\t{}".format(request['call'], json_err), level='info')
    return result

  def _prefix_keys(self, prefix, d):
    """
    Add the specified XML namespace prefix to all keys in the
    passed dict
    """
    if not type(d) == type({}): return d
    new_d = d.copy()
    for k,v in d.items():
      new_key = "{}:{}".format(prefix, k)
      new_v = v
      if type(v) == type({}): new_v = self._prefix_keys(prefix, v)
      new_d[new_key] = new_v 
      del(new_d[k])

    return new_d    

  def _prep_data_for_soap(self, call, details):
    """
    Prepare the complete XML SOAP envelope
    """
    data = xmltodict.unparse(self._prefix_keys('ns1', { call: details }), pretty=False, full_document=False)
    soap_xml = """
    <?xml version="1.0" encoding="UTF-8"?>
    <SOAP-ENV:Envelope xmlns:ns0="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="urn:Manager" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
      <SOAP-ENV:Header/>
        <ns0:Body>
          {}
        </ns0:Body>
    </SOAP-ENV:Envelope>
    """.format(data).strip()

    return soap_xml

  def log(self, message='', err=None, level='info'):
    """
    Log a message
    """
    if not level.lower() in [
      'critical',
      'debug',
      'error',
      'fatal',
      'info',
      'warning'
      ]: level = 'info'

    if err:
      level = 'error'
      message += ' Threw exception:\n\t{}'.format(err)

    try:
      func = getattr(self.logger, level.lower())
      func(message)
    except Exception, log_err:
      self.logger.critical("Could not write to log. Threw exception:\n\t{}".format(log_err))

class CoreDict(dict):
  def __init__(self):
    self._exempt_from_find = []

  def get(self): pass

  def find(self, **kwargs):
    """
    Find any keys where the values match the cumulative kwargs patterns

    If a keyword's value is a list, .find will match on any value for that keyword

    .find(id=1)
    >>> returns any item with a property 'id' and value in [1]
        possibilities:
           { 'id': 1, 'name': 'One'}
           { 'id': 1, 'name': 'Two'}
        
    .find(id=[1,2])
    >>> returns any item with a property 'id' and value in [1,2]
        possibilities:
           { 'id': 1, 'name': 'One'}
           { 'id': 2, 'name': 'One'}
           { 'id': 1, 'name': 'Two'}
           { 'id': 2, 'name': 'Two'}

    .find(id=1, name='One')
    >>> returns any item with a property 'id' and value in [1] AND a property 'name' and value in ['One']
        possibilities:
           { 'id': 1, 'name': 'One'}
        
    .find(id=[1,2], name='One')
    >>> returns any item with a property 'id' and value in [1,2] AND a property 'name' and value in ['One']
        possibilities:
           { 'id': 1, 'name': 'One'}
           { 'id': 2, 'name': 'One'}

    .find(id=[1,2], name=['One,Two'])
    >>> returns any item with a property 'id' and value in [1,2] AND a property 'name' and value in ['One','Two']
        possibilities:
           { 'id': 1, 'name': 'One'}
           { 'id': 2, 'name': 'One'}
           { 'id': 1, 'name': 'Two'}
           { 'id': 2, 'name': 'Two'}
    """
    results = []

    if kwargs:
      for item_id, item in self.items():
        item_matches = False
        for match_attr, match_attr_vals in kwargs.items():
          if not type(match_attr_vals) == type([]): match_attr_vals = [match_attr_vals]

          # does the current item have the property
          attr_to_check = None
          if match_attr in dir(item):
            attr_to_check = getattr(item, match_attr)
          elif 'has_key' in dir(item) and item.has_key(match_attr):
            attr_to_check = item[match_attr]

          if attr_to_check:
            # does the property match the specified values?
            for match_attr_val in match_attr_vals:
              if type(attr_to_check) in [type(''), type(u'')]:
                # string comparison
                match = re.search(r'{}'.format(match_attr_val), attr_to_check)
                if match:
                  item_matches = True
                  break # and move on to the new kwarg
                else:
                  item_matches = False
              elif type(attr_to_check) == type([]):
                # check for the match in the list
                if match_attr_val in attr_to_check:
                  item_matches = True
                  break # and move on to the new kwarg
                else:
                  item_matches = False
              else:
                # object comparison
                if attr_to_check == match_attr_val:
                  item_matches = True
                  break # and move on to the new kwarg
                else:
                  item_matches = False

        if item_matches: results.append(item_id)

    return results

class CoreObject(object):
  def _set_properties(self, api_response, log_func):
    """
    Convert the API keypairs to object properties
    """
    for k, v in api_response.items():
      val = v
      if 'has_key' in dir(v) and v.has_key(u'@xsi:nil') and v[u'@xsi:nil'] == u'true':
        val = None

      new_key = translation.Terms.get(k)

      # make sure any integer IDs are stored as an int
      if new_key == 'id' and re.search('^\d+$', v.strip()): val = int(v)
      if new_key == 'policy_id':
        if '@xsi:nil' in "{}".format(v):
          val = None
        elif re.search('^\d+$', "".join(v.strip())):
          val = int(v)

      try:
        setattr(self, new_key, val)
      except Exception, err:
        if log_func:
          log_func("Could not set property {} to value {} for object {}".format(k, v, s))