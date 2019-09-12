#!/bin/bash

var_exit=0

if [ "$#" -eq 0 ] ; then
	printf "ERROR - No arguments supplied.\n\n"
	var_exit=1
elif [ "$#" -eq 1 ] && [[ "$1" == "-h" || "$1" == "--help" ]] ; then
	var_exit=1
else
	for arg in "$@" ; do
	        if [[ ! "$arg" =~ ^[a-zA-Z0-9\-]+\.[a-zA-Z]{2,11}$ ]] ; then
			if [[ "$arg" != "-h" && "$arg" != "--help" ]] ; then
	                	printf "ERROR - Invalid domain name: $arg \n\n"
			fi
	                var_exit=1
	        fi
	done
fi

if [ "$var_exit" == 1 ] ; then
	printf "Description: This command check IPs in DNSBL blacklists, from a domain name, the command will obtain the associated public IPs, including those of the mail servers (A and MX records).\nUsage: Simply specify from 1 to N domains to consult (without subdomains)\nExample: ./blackListDomainsCheck.sh first-domain.com second-domain.es ... \n\n"
	exit 1
fi

BLISTS="
bl.score.senderscore.com
bl.mailspike.net
bl.spameatingmonkey.net
b.barracudacentral.org
bl.deadbeef.com
bl.emailbasura.org
bl.spamcop.net
blackholes.five-ten-sg.com
blacklist.woody.ch
bogons.cymru.com
cbl.abuseat.org
cdl.anti-spam.org.cn
combined.abuse.ch
combined.rbl.msrbl.net
db.wpbl.info
dnsbl-1.uceprotect.net
dnsbl-2.uceprotect.net
dnsbl-3.uceprotect.net
dnsbl.inps.de
dnsbl.sorbs.net
drone.abuse.ch
drone.abuse.ch
duinv.aupads.org
dul.dnsbl.sorbs.net
dul.ru
dyna.spamrats.com
dynip.rothen.com
http.dnsbl.sorbs.net
images.rbl.msrbl.net
ips.backscatterer.org
ix.dnsbl.manitu.net
korea.services.net
misc.dnsbl.sorbs.net
noptr.spamrats.com
ohps.dnsbl.net.au
omrs.dnsbl.net.au
orvedb.aupads.org
osps.dnsbl.net.au
osrs.dnsbl.net.au
owfs.dnsbl.net.au
owps.dnsbl.net.au
pbl.spamhaus.org
phishing.rbl.msrbl.net
probes.dnsbl.net.au
proxy.bl.gweep.ca
proxy.block.transip.nl
psbl.surriel.com
rbl.interserver.net
rdts.dnsbl.net.au
relays.bl.gweep.ca
relays.bl.kundenserver.de
relays.nether.net
residential.block.transip.nl
ricn.dnsbl.net.au
rmst.dnsbl.net.au
sbl.spamhaus.org
short.rbl.jp
smtp.dnsbl.sorbs.net
socks.dnsbl.sorbs.net
spam.abuse.ch
spam.dnsbl.sorbs.net
spam.rbl.msrbl.net
spam.spamrats.com
spamlist.or.kr
spamrbl.imp.ch
t3direct.dnsbl.net.au
tor.dnsbl.sectoor.de
torserver.tor.dnsbl.sectoor.de
ubl.lashback.com
ubl.unsubscore.com
virbl.bit.nl
virus.rbl.jp
virus.rbl.msrbl.net
web.dnsbl.sorbs.net
wormrbl.imp.ch
xbl.spamhaus.org
zen.spamhaus.org
zombie.dnsbl.sorbs.net
"

for arg in "$@"
do
	IPs=(`dig +short $arg`)
	IPs+=(`dig +short $arg mx | sort -n | nawk '{print $2}' | dig +short -f - `)
	for IP in "${IPs[@]}" ; do
		echo Checking domain: $arg, related IP: $IP
		IPr=`echo $IP | sed -ne "s~^\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)$~\4.\3.\2.\1~p"`
		clean=0
		for BL in ${BLISTS} ; do
			LISTED="$(dig +short -t a ${IPr}.${BL}.)"
			if [ -n "$LISTED" ]
			then
				printf "\e[31m%-60s\e[0m" " - LISTED IN: ${IPr}.${BL}" 
				printf "%s\n" "Response: $LISTED"
				clean=1
			fi
		done
		if [ $clean == 0 ]
		then
			printf "\e[34m%-60s\e[0m\n" " - CLEAN"
		fi
	done
done

