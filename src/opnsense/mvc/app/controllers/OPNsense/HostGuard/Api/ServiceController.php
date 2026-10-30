<?php

/*
 * Copyright (C) 2026 Onur Berkay <onurberkay@sakla.app>
 * All rights reserved. (BSD 2-Clause, see LICENSE)
 */

namespace OPNsense\HostGuard\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\HostGuard\General';
    protected static $internalServiceTemplate = 'OPNsense/HostGuard';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceName = 'hostguard';

    /**
     * download the owner / network type lists now, in the background (takes a minute)
     */
    public function updateipdataAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        (new Backend())->configdRun('hostguard update_ipdata');
        return ['status' => 'ok'];
    }
}
