<?php

/*
 * Copyright (C) 2026 Onur Berkay <onurberkay@sakla.app>
 * All rights reserved. (BSD 2-Clause, see LICENSE)
 */

function hostguard_enabled()
{
    $mdl = new \OPNsense\HostGuard\General();
    return (string)$mdl->enabled == '1';
}

/**
 * register the collector with System: Diagnostics: Services and the services widget
 */
function hostguard_services()
{
    $services = [];

    if (hostguard_enabled()) {
        $services[] = [
            'description' => gettext('HostGuard collector'),
            'configd' => [
                'restart' => ['hostguard restart'],
                'start' => ['hostguard start'],
                'stop' => ['hostguard stop'],
            ],
            'pidfile' => '/var/run/hostguard.pid',
            'name' => 'hostguard',
        ];
    }

    return $services;
}
