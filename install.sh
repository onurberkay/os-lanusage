#!/bin/sh
#
# os-hostguard manual installer for OPNsense
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

chmod 0755 "${PREFIX}/etc/rc.d/hostguard"
chmod 0755 "${PREFIX}"/opnsense/scripts/OPNsense/HostGuard/*.py
mkdir -p /var/db/hostguard "${PREFIX}/etc/hostguard"

# settings: the model migration takes over those of os-lanusage (the earlier name of this plugin)
echo ">> running model migrations"
/usr/local/bin/php /usr/local/opnsense/mvc/script/run_migrations.php OPNsense/HostGuard || true
# run_migrations.php always exits 0: look for the section itself
if grep -q '<lanusage' /conf/config.xml && ! grep -q '<hostguard' /conf/config.xml; then
	echo "!! the os-lanusage settings were not taken over: set them under Reporting > HostGuard > Settings" >&2
fi
# stop os-lanusage and move its database first (the same script runs after a package install) ...
HOSTGUARD_INSTALL_SH=1 sh ./+POST_INSTALL.post
# ... then let pkg remove an os-lanusage package, so that an update does not bring it back
for old in os-lanusage os-lanusage-devel; do
	if pkg info -e "${old}" 2>/dev/null; then
		echo ">> removing the ${old} package"
		pkg delete -y "${old}" || true
		# also from the plugins list in config.xml: a firmware plugin sync would install it again
		if [ -f /usr/local/opnsense/scripts/firmware/register.php ]; then
			/usr/local/bin/php /usr/local/opnsense/scripts/firmware/register.php remove "${old}" || true
		fi
	fi
done

echo ">> clearing menu / ACL caches"
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json

echo ">> restarting configd and generating config"
service configd restart
configctl template reload OPNsense/HostGuard

if grep -q 'hostguard_enable="YES"' /etc/rc.conf.d/hostguard 2>/dev/null; then
	echo ">> restarting collector"
	configctl hostguard restart
fi

echo
echo "Done. Open Reporting > HostGuard > Settings in the web GUI (reload the page first)."
