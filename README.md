# Deep Security AWS WAF Integration

A simple tool set to help build AWS WAF rule sets from Deep Security. 

## Pre-Requisites

```bash
pip install -r requirements.txt
```

## ip_list_to_set.py

Deep Security can host a number of IP Lists (Policies > Common Objects > Lists > IP Lists). These IP Lists can be very useful as AWS WAF IP Sets for matching rule conditions. 

This utility will convert an IP List (IPv6 and IPv4) from Deep Security to a minimized IP Set for use in an AWS WAF rule.

### Usage

Basic command line usage is available by using the ```--help``` switch.

```bash
$ python ip_list_to_set.py --help
>> usage: ip_list_to_set.py [-h] [-d IP_LIST] [-l] [-m DSM] [--dsm-port DSM_PORT]
                         -u USERNAME -p PASSWORD [-t TENANT] [--dryrun]
                         [--verbose]

Deep Security uses the concept of IP Lists to make firewall rules easier to
administer. The AWS WAF uses a similar concept of IP Sets as rule conditions.
This utility helps synchronize Deep Security IP Lists with AWS WAF IP Sets.

optional arguments:
  -h, --help            show this help message and exit
  -d IP_LIST, --ds IP_LIST
                        Specify an IP List within Deep Security as the source
                        for the AWS WAF IP Set
  -l, --list            List the available Deep Security IP Lists and the AWS
                        WAF IP Sets
  -m DSM, --dsm DSM     The address of the Deep Security Manager. Defaults to
                        Deep Security as a Service
  --dsm-port DSM_PORT   The address of the Deep Security Manager. Defaults to
                        Deep Security as a Service
  -u USERNAME, --username USERNAME
                        The Deep Security username to access the IP Lists
                        with. Should only have read-only rights to IP lists
                        and API access
  -p PASSWORD, --password PASSWORD
                        The password for the specified Deep Security username.
                        Should only have read-only rights to IP lists and API
                        access
  -t TENANT, --tenant TENANT
                        The name of the Deep Security tenant/account
  --dryrun              Do a dry run of the command. This will not make any
                        changes to your AWS WAF service
  --verbose             Enabled verbose output for the script. Useful for
                        debugging
```

The first step is to find the ID Deep Security uses for the IP List you want to sync to an AWS WAF IP Set. You can do that using the ```--list``` switch.

```bash
$python ip_list_to_set.py --list -u USERNAME -p PASSWORD -t TENANT
>> Available Deep Security IP Lists
================================
1   Ignore Reconnaissance
2   Network Broadcast
3   Ingress Filters
4   Domain Controller(s)
5   Off Domain IPs
6   Corporate Network IPs
...
```

Once you know the IP List you want to use as the source, you can pass the ID to the script and have it convert the IP List to an AWS WAF IP Set. For most IP Lists, this conversion works well. However for some lists, you'll see a failure based on the size of the IP List.

Deep Security doesn't enforce the same size limits on IP Lists as AWS WAF does on IP Sets. The script attempts to convert the IP List to the smallest possible number of CIDR blocks but can occasionally still run into the 1000 entry limit for an AWS WAF IP Set.

In these cases, the best solution is to divide the list within Deep Security and re-run the script with the new ID(s).

A good practice to adopt is to make a dry run before committing any changes. You can do list using the ```--dryrun``` switch.

```bash
$ python ip_list_to_set.py -d 152 -u USERNAME -p PASSWORD -t TENANT --dryrun
>> ***********************************************************************
* DRY RUN ENABLED. NO CHANGES WILL BE MADE
***********************************************************************
Converted 41 IP List entries to 718 IP Set entries
Will request the addition of 718 entries in IP Set 9ee53a08-cdaf-4881-a111-3d99b58065e4
Will update IP Set [AMAZON eu-west-1] with ID [9ee53a08-cdaf-4881-a111-3d99b58065e4]
```

If you're comfortable with the changes, you can then re-run the script without the ```--dryrun``` switch and commit the changes.

```bash
$ python ip_list_to_set.py -d 152 -u USERNAME -p PASSWORD -t TENANT --dryrun
>> Converted 41 IP List entries to 718 IP Set entries
Updated IP Set [AMAZON eu-west-1] with ID [9ee53a08-cdaf-4881-a111-3d99b58065e4]
```

Now the IP Set has been created in AWS WAF and can be used in a AWS WAC WACL rule as a matching condition. AWS was detailed documentation on [the next steps you need to take](http://docs.aws.amazon.com/waf/latest/developerguide/web-acl.html).

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