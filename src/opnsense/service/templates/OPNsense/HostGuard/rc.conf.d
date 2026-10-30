{% if helpers.exists('OPNsense.hostguard.general.enabled') and OPNsense.hostguard.general.enabled == '1' %}
hostguard_enable="YES"
{% else %}
hostguard_enable="NO"
{% endif %}
