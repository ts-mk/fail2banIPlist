# fail2banIPlist

A Bash script for retrieving list of IP addresses banned by fail2ban.

## Options
- -**c** command (MANDATORY, see below)
- -**h** displays this help
- -**n** number of lines to display (only for the 'latest' command)
- -**o** order of the results (only for the 'all', 'latest' and 'offences' command)
- -**t** threshold of number of offences for an IP to be listed (only for the 'offences' command)
- -**v** displays version of this script

## Commands
- **all** - lists all the bans
- **latest** - lists the latest bans (default 10)
- **offences** - lists number of bans for each unique IP
- **medalists** - lists the top three banned IPs