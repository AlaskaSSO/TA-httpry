#!/bin/bash
# IPs to exclude from HTTPRY (i.e. proxy servers etc)
HTTPRY_EXCLUDE_IPS="10\.231\.255\.111|10\.231\.255\.112|10\.231\.255\.113|10\.230\.255\.111|10\.230\.255\.112|10\.230\.255\.113"
HTTPRY_DESTINATION_SYSLOG="10.231.8.33"
if ! type "nc" > /dev/null 2>&1; then
echo "nc not found; recommend running:"
echo "apt-get install netcat"
fi
if ! type "uniq" >/dev/null 2>&1; then
echo "uniq not found; recommend running:"
echo "apt-get install coreutils"
fi
if ! type "rev" >/dev/null 2>&1; then
echo "rev not found; recommend running:"
echo "apt-get install rev"
fi
if ! type "mbuffer" >/dev/null 2>&1; then
echo "mbuffer not found; recommend running:"
echo "apt-get install mbuffer"
fi
#perl -MCPAN -e shell
#install  Daemon::Daemonize
#Net::Server::Daemonize
#URI::Escape::XS
#Config::JSON
#Math::Round
#Log::Syslog::Fast
killall httpry_logger.pl >/dev/null 2>/dev/null
sleep 1
killall httpry_logger.pl >/dev/null 2>/dev/null
sleep 1
killall httpry_logger.pl >/dev/null 2>/dev/null
sleep 1
killall httpry_logger.pl >/dev/null 2>/dev/null
sleep 1
killall httpry_logger.pl >/dev/null 2>/dev/null
sleep 5
/usr/local/bin/httpry_logger.pl -c /etc/httpry.config  -d |grep httpry|egrep -v $HTTPRY_EXCLUDE_IPS|uniq -u|rev|egrep -v "^\|\|0\|\-\|\-\|\-\|\-\|\-\|\-\|"|rev|uniq -u|mbuffer -q -m 128M|nc $HTTPRY_DESTINATION_SYSLOG -q 86400 1515 >/dev/null 2>/dev/null &
sleep 12
pidof /usr/sbin/httpry > /var/run/httpry.pid
netstat -anp|grep nc|grep "0      0"|grep -v ESTABLISHED|tr -s ' '|cut -f 7 -d ' '|grep nc|cut -f 1 -d'/'|xargs -i kill {}
ps axuw|grep mbuffer |grep -v "0.0"|tr -s ' '|cut -f2 -d ' '|xargs -i kill {}

