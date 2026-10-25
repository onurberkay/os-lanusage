#!/bin/sh
#
# os-lanusage manual installer for OPNsense
# usage: sh install.sh
#
set -e

cd "$(dirname "$0")"
PREFIX=/usr/local

if [ "$(id -u)" != "0" ]; then
	echo "run as root" >&2
	exit 1
fi

echo ">> copying files to ${PREFIX}"
(cd src && find . -type f) | while read -r f; do
	f="${f#./}"
	mkdir -p "$(dirname "${PREFIX}/${f}")"
	install -m 0644 "src/${f}" "${PREFIX}/${f}"
done

chmod 0755 "${PREFIX}/etc/rc.d/lanusage"
chmod 0755 "${PREFIX}"/opnsense/scripts/OPNsense/LanUsage/*.py
mkdir -p /var/db/lanusage "${PREFIX}/etc/lanusage"

echo ">> clearing menu / ACL caches"
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json

echo ">> restarting configd and generating config"
service configd restart
configctl template reload OPNsense/LanUsage

if grep -q 'lanusage_enable="YES"' /etc/rc.conf.d/lanusage 2>/dev/null; then
	echo ">> restarting collector"
	configctl lanusage restart
fi

echo
echo "Done. Open Reporting > LAN Usage > Settings in the web GUI (reload the page first)."
