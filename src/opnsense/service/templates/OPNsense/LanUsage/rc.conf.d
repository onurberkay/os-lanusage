{% if helpers.exists('OPNsense.lanusage.general.enabled') and OPNsense.lanusage.general.enabled == '1' %}
lanusage_enable="YES"
{% else %}
lanusage_enable="NO"
{% endif %}
