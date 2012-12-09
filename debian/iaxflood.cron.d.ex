#
# Regular cron jobs for the iaxflood package
#
0 4	* * *	root	[ -x /usr/bin/iaxflood_maintenance ] && /usr/bin/iaxflood_maintenance
