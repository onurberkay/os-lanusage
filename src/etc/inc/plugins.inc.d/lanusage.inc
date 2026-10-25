<?php

/*
 * Copyright (C) 2026 Onur Berkay <onurberkay@sakla.app>
 * All rights reserved. (BSD 2-Clause, see LICENSE)
 */

function lanusage_enabled()
{
    $mdl = new \OPNsense\LanUsage\General();
    return (string)$mdl->enabled == '1';
}

/**
 * register the collector with System: Diagnostics: Services and the services widget
 */
function lanusage_services()
{
    $services = [];

    if (lanusage_enabled()) {
        $services[] = [
            'description' => gettext('LAN usage collector'),
            'configd' => [
                'restart' => ['lanusage restart'],
                'start' => ['lanusage start'],
                'stop' => ['lanusage stop'],
            ],
            'pidfile' => '/var/run/lanusage.pid',
            'name' => 'lanusage',
        ];
    }

    return $services;
}
