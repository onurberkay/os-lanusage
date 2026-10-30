<?php

/*
 * Copyright (C) 2026 Onur Berkay <onurberkay@sakla.app>
 * All rights reserved. (BSD 2-Clause, see LICENSE)
 */

namespace OPNsense\HostGuard\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'general';
    protected static $internalModelClass = 'OPNsense\HostGuard\General';

    /**
     * remove the collected data (settings privilege: it also forgets the known LAN hosts)
     */
    public function clearAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $response = (new Backend())->configdRun('hostguard clear');
        $data = json_decode((string)$response, true);
        return is_array($data) ? $data : ['status' => 'error', 'message' => trim((string)$response)];
    }
}
