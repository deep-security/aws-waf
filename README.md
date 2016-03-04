# Deep Security AWS WAF Integration

A simple tool set to help build AWS WAF rule sets from Deep Security. 

## Pre-Requisites

```bash
pip install -r requirements.txt
```

### Usage

Basic command line usage is available by using the ```--help``` switch.

```bash
$ python ds-to-aws-waf.py
usage: ds-to-aws-waf [COMMAND]
   For more help on a specific command, type ds-to-aws-waf [COMMAND] --help

   Available commands:

   iplist
      > Push a Deep Security IP list to an AWS WAF IP Set
   sqli
      > Determine which instances protected by Deep Security should also be protected by AWS WAF SQLi rules
   ...
```


## SSL Certificate Validation

If the Deep Security Manager (DSM) you're connecting to was installed via software of the AWS Marketplace, there's a chance that it is still using the default, self-signed SSL certificate. By default, python checks the certificate for validity which it cannot do with self-signed certificates.

If you are using self-signed certificates, please use the new ```--ignore-ssl-validation``` command line flag.

When you use this flag, you're telling python to ignore any certificate warnings. These warnings should be due to the self-signed certificate but *could* be for other reasons. It is strongly recommended that you have alternative mitigations in place to secure your DSM. 

When the flag is set, you'll see this warning block;

```bash
***********************************************************************
* IGNORING SSL CERTIFICATE VALIDATION
* ===================================
* You have requested to ignore SSL certificate validation. This is a less secure method 
* of connecting to a Deep Security Manager (DSM). Please ensure that you have other 
* mitigations and security controls in place (like restricting IP space that can access 
* the DSM, implementing least privilege for the Deep Security user/role accessing the 
* API, etc).
*
* During script execution, you'll see a number of "InsecureRequestWarning" messages. 
* These are to be expected when operating without validation. 
***********************************************************************
```

And during execution you may see lines similar to;

```python
.../requests/packages/urllib3/connectionpool.py:789: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.org/en/latest/security.html
```

These are expected warnings. Can you tell that we (and the python core teams) are trying to tell you something? If you're interesting in using a valid SSL certificate, you can get one for free from [Let's Encrypt](https://letsencrypt.org), [AWS themselves](https://aws.amazon.com/certificate-manager/) (if your DSM is behind an ELB), or explore commercial options (like the [one from Trend Micro](http://www.trendmicro.com/us/enterprise/cloud-solutions/deep-security/ssl-certificates/)).