# Deep Security AWS WAF Integration

A simple tool set to help build AWS WAF rule sets from Deep Security. 

## Pre-Requisites

```bash
pip install -r requirements.txt
```

### Basic Usage

The syntax for basic command line usage is available by using the ```--help``` switch.

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

Each script in this set works under a common structure. There are several shared arguments;

```bash
  -h, --help            show this help message and exit
  -d DSM, --dsm DSM     The address of the Deep Security Manager. Defaults to
                        Deep Security as a Service
  --dsm-port DSM_PORT   The address of the Deep Security Manager. Defaults to
                        an AWS Marketplace/software install (:4119).
                        Automatically configured for Deep Security as a
                        Service
  -u DSM_USERNAME, --dsm-username DSM_USERNAME
                        The Deep Security username to access the IP Lists
                        with. Should only have read-only rights to IP lists
                        and API access
  -p DSM_PASSWORD, --dsm-password DSM_PASSWORD
                        The password for the specified Deep Security username.
                        Should only have read-only rights to IP lists and API
                        access
  -t DSM_TENANT, --dsm-tenant DSM_TENANT
                        The name of the Deep Security tenant/account
  --ignore-ssl-validation
                        Ignore SSL certification validation. Be careful when
                        you use this as it disables a recommended security
                        check. Required for Deep Security Managers using a
                        self-signed SSL certificate
  --dryrun              Do a dry run of the command. This will not make any
                        changes to your AWS WAF service
  --verbose             Enabled verbose output for the script. Useful for
                        debugging
```

These core settings allow you to connect to a Deep Security manager or Deep Security as a Service. 

```bash
# to connect to your own Deep Security manager
ds-to-aws-waf [COMMAND] -d 10.1.1.0 -u admin -p USE_RBAC_TO_REDUCE_RISK --ignore-ssl-validation

# to connect to Deep Security as a Service
ds-to-aws-waf [COMMAND] -u admin -p USE_RBAC_TO_REDUCE_RISK -t MY_ACCOUNT
```

Each individual command will also have it's own options that allow you to control the behaviour of the command.

You'll notice in the examples, the password is set to USE_RBAC_TO_REDUCE_RISK. In this context, RBAC stands for role based access control.

Currently Deep Security treats API access just like a user logging in. Therefore it is strongly recommended that you create a new Deep Security user for use with this script. This user should have the bare minimum permissions required to complete the tasks.

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

The commands available in this repository are designed to help you build better rule sets for AWS WAF based on what Deep Security understands about your workloads.

There are charges associated with pushing new rules to AWS WAF. **Always check the [AWS WAF pricing page](https://aws.amazon.com/waf/pricing/) for the latest prices.**

AWS WAF charges for each web access control list (WACL), for each rule, and for the number of requests processed. This is in addition to any associated AWS CloudFront charges.

We've done our best to ensure that each command optimizes the changes it makes in AWS WAF in order to reduce your costs. In general, you can run a command with the ```--dryrun``` option to see the results without making changes and before incurring any costs.

### iplists

The *iplists* command does not create a WACL or rule on your behalf. It creates new IPSet objects that can be used in an AWS WAF rule as a match condition. There are no charges for these IPSets.

### sqli

The *sqli* command designs a set of rules to help complete your AWS WAF deployment. There are charges associated with each rule that the script creates.

The script can be run in ```--dryrun``` to see the end result before pushing the rules to AWS. This can help you get a better idea of the cost associated with the new rule set.