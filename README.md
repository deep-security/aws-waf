# Deep Security AWS WAF Integration

A simple tool set to help build AWS WAF rule sets from Deep Security. 

## Pre-Requisites

```bash
pip install -r requirements.txt
```

## ip_list_to_set.py

Deep Security can host a number of IP Lists (Policies > ... > IP Lists). These IP Lists can be very useful as AWS WAF IP Sets for matching rule conditions. 

This utility will convert an IP List (IPv6 and IPv4) from Deep Security to a minimized IP Set for use in an AWS WAF rule.

### Usage

Basic command line usage is available by using the ```--help``` switch.

```bash
$ python ip_list_to_set.py --help
>> usage: ip_list_to_set.py [-h] [-d IP_LIST] [-l] [-m DSM] -u USERNAME -p
                         PASSWORD [-t TENANT]

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

```bash
$ python ip_list_to_set.py -d 152 -u USERNAME -p PASSWORD -t TENANT
>> Found Deep Security IP list [IpList 152 <AMAZON eu-west-1>]
New AWS WAF change token [ed8d5d55-5b3a-456e-b7b5-39f73a5450ae]
Expanded CIDR block 46.51.128.0/18 to 64 IP Set compatible blocks
Expanded CIDR block 46.51.192.0/20 to 16 IP Set compatible blocks
...
Expanded CIDR block 176.34.128.0/17 to 128 IP Set compatible blocks
Expanded CIDR block 178.236.0.0/20 to 16 IP Set compatible blocks
Expanded CIDR block 185.48.120.0/22 to 4 IP Set compatible blocks
Converted 41 IP List entries to 718 IP Set entries
Change [ed8d5d55-5b3a-456e-b7b5-39f73a5450ae] requested
```
