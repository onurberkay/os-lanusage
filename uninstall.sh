#!/bin/sh
#
# os-hostguard manual uninstaller for OPNsense
# usage: sh uninstall.sh [--purge]     (--purge also removes the collected database)
#
cd "$(dirname "$0")"
PREFIX=/usr/local

if [ -x "${PREFIX}/etc/rc.d/hostguard" ]; then
	"${PREFIX}/etc/rc.d/hostguard" onestop
fi

echo ">> removing files"
(cd src && find . -type f) | while read -r f; do
	rm -f "${PREFIX}/${f#./}"
done
rm -rf "${PREFIX}/opnsense/scripts/OPNsense/HostGuard" \
       "${PREFIX}/opnsense/mvc/app/controllers/OPNsense/HostGuard" \
       "${PREFIX}/opnsense/mvc/app/models/OPNsense/HostGuard" \
       "${PREFIX}/opnsense/mvc/app/views/OPNsense/HostGuard" \
       "${PREFIX}/opnsense/service/templates/OPNsense/HostGuard" \
       "${PREFIX}/etc/hostguard" /etc/rc.conf.d/hostguard

if [ "$1" = "--purge" ]; then
	echo ">> removing database"
	rm -rf /var/db/hostguard
fi

rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json
service configd restart
echo "Done. Settings stay in config.xml (OPNsense/hostguard) and are ignored without the plugin."
echo "Addresses block conditions put into <virusprot> stay there until it is flushed:"
echo "  pfctl -t virusprot -T show    (pfctl -t virusprot -T flush clears it, pf overload entries too)"
