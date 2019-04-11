# DnsblDomainsChecker.sh

Description: Bash script that check IPs in DNSBL blacklists, from a domain name, the command will obtain the associated public IPs, including those of the mail servers (A and MX records).

Usage: Simply specify from 1 to N domains to consult (without subdomains).

Example: ./blackListDomainsCheck.sh first-domain.com second-domain.es ...
