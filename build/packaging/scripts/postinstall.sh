#!/bin/sh

U="spks"
HOMEDIR="/var/lib/spks"

id -u $U >/dev/null 2>&1 || useradd -r -d $HOMEDIR -M -U -s /bin/false -c "$U server" $U
chmod 700 $HOMEDIR
chown $U:root $HOMEDIR

exit 0
