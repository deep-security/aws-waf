import ssl
import urllib2
from suds.transport.http import HttpTransport, Reply, TransportError

class HTTPSIgnoreValidation(HttpTransport):
    """
    An HTTPS Handler set to ignore SSL certificate validation

    The software and AWS Marketplace installations of Deep Security default to using 
    a self-signed certificate and require this handler for SOAP API access

    With help from;
      @nitwit via http://stackoverflow.com/questions/6277027/suds-over-https-with-cert
      @enno groper via http://stackoverflow.com/questions/19268548/python-ignore-certicate-validation-urllib2
    """
    def __init__(self, *args, **kwargs): HttpTransport.__init__(self, *args, **kwargs)
    
    def u2open(self, u2request):
        """
        Open a connection.
        @param u2request: A urllib2 request.
        @type u2request: urllib2.Requet.
        @return: The opened file-like urllib2 object.
        @rtype: fp
        """
        tm = self.options.timeout
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return urllib2.urlopen(u2request, context=ctx)