> This commit has breaking changes that will stay firm moving forward. For original, early adopters please use [release v0.91](https://github.com/deep-security/aws-waf/releases/tag/v0.91)...but move to the current one when you can, it's **way better** ;-)

# Deep Security AWS WAF Integration

A simple tool set to help build AWS WAF rule sets based on intelligence from Deep Security. 

## Support

This is a community project and while you will see contributions from the Deep Security team, there is no official Trend Micro support for this project. The official documentation for the Deep Security APIs is available from the [Trend Micro Online Help Centre](http://docs.trendmicro.com/en-us/enterprise/deep-security.aspx). 

Tutorials, feature-specific help, and other information about Deep Security is available from the [Deep Security Help Center](https://help.deepsecurity.trendmicro.com/Welcome.html). 

For Deep Security specific issues, please use the regular Trend Micro support channels. For issues with the code in this repository, please [open an issue here on GitHub](https://github.com/deep-security/aws-waf/issues).


## Index

- [Pre-Requisites](#pre-requisites)
- [Usage](#usage)
   - [iplists](#usage-iplists)
   - [sqli & xss](#usage-sqli-xss)
- [SSL Certificate Validation](#ssl-certificate-validation)
- [AWS WAF Costs](#aws-waf-costs)
  - [iplists](#aws-waf-costs-iplists)
  - [sqli & xss](#aws-waf-costs-sqli-xss)

<a name="pre-requisites" />

## Pre-Requisites

```bash
pip install -r requirements.txt
```

<a name="usage" />

### Usage

The syntax for basic command line usage is available by using the ```--help``` switch.

```bash
$ python ds-to-aws-waf.py
usage: ds-to-aws-waf [COMMAND]
   For more help on a specific command, type ds-to-aws-waf [COMMAND] --help

   Available commands:

   iplist
      > Push a Deep Security IP list to an AWS WAF IP Set
   xss
      > Determine which instances protected by Deep Security should also be protected by AWS WAF XSS rules
   sqli
      > Determine which instances protected by Deep Security should also be protected by AWS WAF SQLi rules
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
  -a AWS_ACCESS_KEY, --aws-access-key AWS_ACCESS_KEY
                        The access key for an IAM identity in the AWS account
                        to connect to
  -s AWS_SECRET_KEY, --aws-secret-key AWS_SECRET_KEY
                        The secret key for an IAM identity in the AWS account
                        to connect to
  -r AWS_REGION, --aws-region AWS_REGION
                        The name of AWS region to connect to                        
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

<a name="usage-iplists" />

### iplists

The iplists command is a simple, two-step process. You must first find the ID of the list in Deep Security and then push that IP list to an AWS WAF IP set.

**Step 1;**

```
# list the available IP lists in Deep Security
# ...for Deep Security as a Service
python ds-to-aws-waf.py iplists -u WAF -p PASSWORD -t TENANT -l

# ...for another Deep Security manager
python ds-to-aws-waf.py iplists -u WAF -p PASSWORD -d DSM_HOSTNAME --ignore-ssl-validation -l
```

This command will then display a list of IP lists and their associated IDs. You can then use those IDs to push the IP list to AWS WAF as an IP Set.

**Step 2;**

```
# push a Deep Security IP list to an AWS WAF IP Set
# ...for Deep Security as a Service
python ds-to-aws-waf.py iplists -u WAF -p PASSWORD -t TENANT -i 17

# ...for another Deep Security manager
python ds-to-aws-waf.py iplists -u WAF -p PASSWORD -d DSM_HOSTNAME --ignore-ssl-validation -i 17
```

The complete command syntax is;

```
 # ./ds-to-aws-waf.py iplists --help
usage: ds-to-aws-waf.py iplists [-h] [-d DSM] [--dsm-port DSM_PORT] -u
                                DSM_USERNAME -p DSM_PASSWORD [-t DSM_TENANT]
                                [-r AWS_REGION] [--ignore-ssl-validation]
                                [--dryrun] [--verbose] [-l] [-i IP_LIST]

Create and update AWS WAF WACL rules based on information from a Deep Security
installation

optional arguments:
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
  -a AWS_ACCESS_KEY, --aws-access-key AWS_ACCESS_KEY
                        The access key for an IAM identity in the AWS account
                        to connect to
  -s AWS_SECRET_KEY, --aws-secret-key AWS_SECRET_KEY
                        The secret key for an IAM identity in the AWS account
                        to connect to                        
  -r AWS_REGION, --aws-region AWS_REGION
                        The name of AWS region to connect to
  --ignore-ssl-validation
                        Ignore SSL certification validation. Be careful when
                        you use this as it disables a recommended security
                        check. Required for Deep Security Managers using a
                        self-signed SSL certificate
  --dryrun              Do a dry run of the command. This will not make any
                        changes to your AWS WAF service
  --verbose             Enabled verbose output for the script. Useful for
                        debugging
  -l, --list            List the available Deep Security IP Lists and the AWS
                        WAF IP Sets
  -i IP_LIST, --id IP_LIST
                        Specify an IP List by ID within Deep Security as the
                        source for the AWS WAF IP Set
```

<a name="usage-sqli-xss" />

### sqli & xss

The sqli and xss commands contain two parts; the analysis of the workloads on the specified EC2 instances and the creation of an SQLi/XSS match condition. These two commands work in the exact same manner. The only difference is the initial command of ```sqli``` or ```xss```.

You can run either part separately, though **the creation of the match condition only needs to be run once per account.**

Common usage;

```
# create a new SQLi or XSS match condition 
# ...for Deep Security as a Service
python ds-to-aws-waf.py sqli -u WAF -p PASSWORD -t TENANT --create-match
python ds-to-aws-waf.py xss -u WAF -p PASSWORD -t TENANT --create-match

# ...for another Deep Security manager
python ds-to-aws-waf.py sqli -u WAF -p PASSWORD -d DSM_HOSTNAME --ignore-ssl-validation --create-match
python ds-to-aws-waf.py xss -u WAF -p PASSWORD -d DSM_HOSTNAME --ignore-ssl-validation --create-match
```

To find out which instances should be protected by an AWS WAF SQLi or XSS rule;

```
# find out which instances should be protected by an AWS WAF SQLi rule
# ...for Deep Security as a Service
python ds-to-aws-waf.py sqli -u WAF -p PASSWORD -t TENANT -l
python ds-to-aws-waf.py xss -u WAF -p PASSWORD -t TENANT -l

# ...for another Deep Security manager
python ds-to-aws-waf.py sqli -u WAF -p PASSWORD -d DSM_HOSTNAME --ignore-ssl-validation -l
python ds-to-aws-waf.py xss -u WAF -p PASSWORD -d DSM_HOSTNAME --ignore-ssl-validation -l

# filter those instances by tag and region
# ...for Deep Security as a Service
python ds-to-aws-waf.py sqli -u WAF -p PASSWORD -t TENANT -l --tag Name=Test --tag Environment=PROD -r us-east-1
python ds-to-aws-waf.py xss -u WAF -p PASSWORD -t TENANT -l --tag Name=Test --tag Environment=PROD -r us-east-1

# ...for another Deep Security manager
python ds-to-aws-waf.py sqli -u WAF -p PASSWORD -d DSM_HOSTNAME --ignore-ssl-validation -l --tag Name=Test --tag Environment=PROD -r us-east-1
python ds-to-aws-waf.py xss -u WAF -p PASSWORD -d DSM_HOSTNAME --ignore-ssl-validation -l --tag Name=Test --tag Environment=PROD -r us-east-1

```

The complete command syntax is;

```
usage: ds-to-aws-waf.py (sqli|xss) [-h] [-d DSM] [--dsm-port DSM_PORT] -u
                             DSM_USERNAME -p DSM_PASSWORD [-t DSM_TENANT]
                             [-r AWS_REGION] [--ignore-ssl-validation]
                             [--dryrun] [--verbose] [-l]
                             [--tag TAGS [TAGS ...]] [--create-match]
                             [--map-to-wacl]

Create and update AWS WAF WACL rules based on information from a Deep Security
installation

optional arguments:
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
  -a AWS_ACCESS_KEY, --aws-access-key AWS_ACCESS_KEY
                        The access key for an IAM identity in the AWS account
                        to connect to
  -s AWS_SECRET_KEY, --aws-secret-key AWS_SECRET_KEY
                        The secret key for an IAM identity in the AWS account
                        to connect to                        
  -r AWS_REGION, --aws-region AWS_REGION
                        The name of AWS region to connect to
  --ignore-ssl-validation
                        Ignore SSL certification validation. Be careful when
                        you use this as it disables a recommended security
                        check. Required for Deep Security Managers using a
                        self-signed SSL certificate
  --dryrun              Do a dry run of the command. This will not make any
                        changes to your AWS WAF service
  --verbose             Enabled verbose output for the script. Useful for
                        debugging
  -l, --list            List the available EC2 instances
  --tag TAGS [TAGS ...]
                        Specify the tags to filter the EC2 instances by. Multiple tags are cumulative
  --create-match        Create the SQLi match condition for use in various
                        rules
  --map-to-wacl         Attempt to map each instance to an AWS WAF WACL
  --create-rule         Create the SQLi rule for instances that can be mapped
                        to an AWS WAF WACL. Used in conjunction with -l/--list
```

<a name="ssl-certificate-validation" />

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

<a name="aws-waf-costs" />

## AWS WAF Costs

The commands available in this repository are designed to help you build better rule sets for AWS WAF based on what Deep Security understands about your workloads.

There are charges associated with pushing new rules to AWS WAF. **Always check the [AWS WAF pricing page](https://aws.amazon.com/waf/pricing/) for the latest prices.**

AWS WAF charges for each web access control list (WACL), for each rule, and for the number of requests processed. This is in addition to any associated AWS CloudFront charges.

We've done our best to ensure that each command optimizes the changes it makes in AWS WAF in order to reduce your costs. In general, you can run a command with the ```--dryrun``` option to see the results without making changes and before incurring any costs.

<a name="aws-waf-costs-iplists" />

### iplists

The *iplists* command does not create a WACL or rule on your behalf. It creates new IPSet objects that can be used in an AWS WAF rule as a match condition. There are no charges for these IPSets.

<a name="aws-waf-costs-sqli-xss" />

### sqli & xss

The *sqli* and *xss* commands provide recommendation as to which instances should be protected by an rule with an SQLi match set. Additionally, you can ask the command to create an SQLi or XSS match set that covers most web applications.

There is no charge for the match set. Charge start when you create a rule using the match set.

If you run the script with the ```--create-rule``` option, the script will create an AWS WAF Rule is it can determine which WACL is protecting the instances the recommendation is based on. 

With this option enabled, you will start to incur charges from AWS for as long as the rule is associated with a WACL. Please refer to the [AWS WAF Pricing](http://aws.amazon.com/waf/pricing/) page for the latest information.

The script can be run in ```--dryrun``` to see the end result before pushing the match set to AWS. This can help you get a better idea of what is being created.

## Support

This is an Open Source community project. Project contributors may be able to help, 
depending on their time and availability. Please be specific about what you're 
trying to do, your system, and steps to reproduce the problem.

For bug reports or feature requests, please 
[open an issue](../issues). 
You are welcome to [contribute](#contribute).

Official support from Trend Micro is not available. Individual contributors may be 
Trend Micro employees, but are not official support.

## Contribute

We accept contributions from the community. To submit changes:

1. Fork this repository.
1. Create a new feature branch.
1. Make your changes.
1. Submit a pull request with an explanation of your changes or additions.

We will review and work with you to release the code.
