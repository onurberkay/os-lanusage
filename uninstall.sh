#!/bin/sh
#
# os-lanusage manual uninstaller for OPNsense
# usage: sh uninstall.sh [--purge]     (--purge also removes the collected database)
#
cd "$(dirname "$0")"
PREFIX=/usr/local

if [ -x "${PREFIX}/etc/rc.d/lanusage" ]; then
	"${PREFIX}/etc/rc.d/lanusage" onestop
fi

echo ">> removing files"
(cd src && find . -type f) | while read -r f; do
	rm -f "${PREFIX}/${f#./}"
done
rm -rf "${PREFIX}/opnsense/scripts/OPNsense/LanUsage" \
       "${PREFIX}/opnsense/mvc/app/controllers/OPNsense/LanUsage" \
       "${PREFIX}/opnsense/mvc/app/models/OPNsense/LanUsage" \
       "${PREFIX}/opnsense/mvc/app/views/OPNsense/LanUsage" \
       "${PREFIX}/opnsense/service/templates/OPNsense/LanUsage" \
       "${PREFIX}/etc/lanusage" /etc/rc.conf.d/lanusage

if [ "$1" = "--purge" ]; then
	echo ">> removing database"
	rm -rf /var/db/lanusage
fi

rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json
service configd restart
echo "Done. Settings stay in config.xml (OPNsense/lanusage) and are ignored without the plugin."
