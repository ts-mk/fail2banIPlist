#!/bin/bash

# TODO
# * Country of the medalists

version='1.1.0'
self=`basename $0`
logfolder=/var/log
usage="Usage: $self [options]

Options:
  -c command (MANDATORY, see below)
  -h displays this help
  -n number of lines to display (only for the 'latest' command)
  -o order of the results (only for the 'all', 'latest' and 'offences' command)
  -t threshold of number of offences for an IP to be listed (only for the 'offences' command)
  -v displays version of this script

Commands:
  current - lists currently banned IP addresses
  all - lists all the bans
  latest - lists the latest bans (default 10)
  offences - lists number of bans for each unique IP
  medalists - lists the top three banned IPs

Author:
  Tomas Mrozek <mail@cascaval.com>

License:
  Copyright (C) 2015 Tomas Mrozek

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program. If not, see <http://www.gnu.org/licenses/>."


# Handling of arguments
command=''
lines=''
order=''
threshold=''

while getopts ":c:n:o:t:vh" option; do
	case $option in
		c)
			command=$OPTARG
			;;

		h)
			printf '%s\n' "$usage"
			exit 0
			;;

		n)
			lines=$OPTARG
			re='^[0-9]+$'
			if ! [[ $lines =~ $re ]] ; then
				echo "An integer was expected for the option -$option"
				exit 1
			fi
			;;

		o)
			case $OPTARG in
				asc)
					order='asc'
					;;

				desc)
					order='desc'
					;;

				*)
					echo "Invalid argument '$OPTARG' for option -$option"
					exit 1
					;;
			esac
			;;

		t)
			threshold=$OPTARG
			re='^[0-9]+$'
			if ! [[ $threshold =~ $re ]] ; then
				echo "An integer was expected for the option -$option"
				exit 1
			fi
			;;

		v)
			echo "Version: $version"
			exit 0
			;;

		\?)
			echo "Invalid option -$OPTARG"
			exit 1
			;;
		:)
			echo "Option -$OPTARG requires an argument"
			exit 1
			;;
	esac
done


# Running the command
case "$command" in
	current)
		if [ $USER == "root" ]; then
			prefix=""
		else
			prefix="sudo "
		fi

		chains=`$prefix iptables -n -L | grep -iE '^Chain fail2ban-' | sed -r 's/.*(fail2ban-[^ ]+).*/\1/g'`
		for chain in $chains; do
			jail=`echo "$chain" | sed -r s/fail2ban-//`
			ban=`$prefix iptables -n -L "$chain" | grep -iE '^(REJECT|DROP)' | awk -v jail="$jail" '{ print jail" "$4 }'`
			content="$content\n$ban"
		done

		echo -e "$content" | \
		(echo "JAIL IP"; cat) | \
		column -t
		;;

	all)
		if [ "$order" == 'desc' ]; then
			order='r'
		else
			order=''
		fi

		zgrep -h " Ban " "$logfolder/fail2ban.log"* | \
		sed -r 's/[^:]+:([^,]+)[^\[]+\[([^]]+)\] Ban (.+)/\1 \2 \3/g' | \
		sort -t " " -k 1.1,1.4n"$order" -k 1.6,1.7n"$order" -k 1.9,1.10n"$order" -k 2.1,2.2n"$order" -k 2.4,2.5n"$order" -k 2.7,2.8n"$order" | \
		(echo "DATE TIME JAIL IP"; cat) | \
		column -t
		;;

	latest)
		if [ "$order" == 'asc' ]; then
			order=''
		else
			order='r'
		fi

		if [ "$lines" == "" ] || [ "$lines" -lt 0 ]; then
			lines=10
		fi

		zgrep -h " Ban " "$logfolder/fail2ban.log"* | \
		sed -r 's/[^:]+:([^,]+)[^\[]+\[([^]]+)\] Ban (.+)/\1 \2 \3/g' | \
		sort -t " " -k 1.1,1.4nr -k 1.6,1.7nr -k 1.9,1.10nr -k 2.1,2.2nr -k 2.4,2.5nr -k 2.7,2.8nr | \
		head -n $lines | \
		sort -t " " -k 1.1,1.4n"$order" -k 1.6,1.7n"$order" -k 1.9,1.10n"$order" -k 2.1,2.2n"$order" -k 2.4,2.5n"$order" -k 2.7,2.8n"$order" | \
		(echo "DATE TIME JAIL IP"; cat) | \
		column -t
		;;

	offences)
		if [ "$order" == 'asc' ]; then
			order=''
		else
			order='r'
		fi

		if [ "$threshold" != "" ]; then
			zgrep -h " Ban " "$logfolder/fail2ban.log"* | \
			awk '{ print $7 }' | \
			sort | \
			uniq -c | \
			awk -v threshold="$threshold" '{ if($1 >= threshold) print $0; }' | \
			sort -n$order | \
			(echo "IP OFFENCES"; awk '{ print $2" "$1 }') | \
			column -t
		else
			zgrep -h " Ban " "$logfolder/fail2ban.log"* | \
			awk '{ print $7 }' | \
			sort | \
			uniq -c | \
			sort -n$order | \
			(echo "IP OFFENCES"; awk '{ print $2" "$1 }') | \
			column -t
		fi
		;;

	medalists)
		zgrep -h " Ban " "$logfolder/fail2ban.log"* | \
		awk '{ print $7 }' | \
		sort | \
		uniq -c | \
		sort -rn | \
		head -n 3 | \
		awk '{ if(NR == 1) printf "Gold"; if(NR == 2) printf "Silver"; if(NR == 3) printf "Bronze"; print " "$1" "$2 }' | \
		(echo "MEDAL OFFENCES IP"; cat) | \
		column -t
		;;

	*)
		printf '%s\n' "$usage"
		exit 1
		;;
esac

exit 0
