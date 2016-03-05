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

## AWS WAF Costs

https://aws.amazon.com/waf/pricing/

AWS WAF charges based on the number of web access control lists (web ACLs) that you create, the number of rules that you add per web ACL, and the number of web requests that you receive. There are no upfront commitments. AWS WAF charges are in addition to Amazon CloudFront Pricing.
Web Access Control List and Rule Charges

AWS WAF charges based on the number of web ACLs that you create and the number of rules that you add per web ACL. Web ACLs and their added rules are metered regardless of whether they are associated with a CloudFront distribution. There is no additional charge for reusing web ACLs across mulitple CloudFront distributions; however, you are charged for each rule added to each web ACL.
Web Access Control List Charges

$5 per web ACL per month

Rule Charges

$1 per rule per web ACL per month

Request Charges

AWS WAF also charges for the amount of web request AWS WAF handles. This is based upon the number of web requests the application receives.

Request Charge

$0.60 per million web requests
Manage Your AWS Resources

Sign in to the Console
Pricing Example
Let’s assume you start using AWS WAF at the first of the month to protect eight CloudFront web distributions. For this example, we’ll create two web ACLs, one web ACL with four rules associated to six CloudFront web distributions, and another web ACL with six rules associated to two remaining CloudFront web distributions. The CloudFront web distributions are expected to receive 10 million requests per month in total.

Web ACL

Web ACL charge = # of web ACLs per month * $5

Total web ACL charge = 2 * $5 = $10

Rule

The price for a rule is $1 per month (pro-rated by the hour)

Rule charge = # of rules associated per month * $1

Total rule charge = (4 + 6) * $1 = $10

Request

The price for request is $0.60 per million

Request charge = # of requests per month (in millions) * $0.60

Total request charge = 10 million requests * $0.60 = $6.00

Total Monthly Bill

Total web ACL charge + total rule charge + total request charge = $10 + $10 + $6 = $26