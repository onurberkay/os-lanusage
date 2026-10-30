<?php

/*
 * Copyright (C) 2026 Onur Berkay <onurberkay@sakla.app>
 * All rights reserved. (BSD 2-Clause, see LICENSE)
 */

namespace OPNsense\HostGuard\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Block conditions: they change the virusprot pf table, so they have their own privilege
 * ("Firewall: HostGuard: Block conditions"); the reporting privilege only reads them.
 */
class ConditionsController extends ApiControllerBase
{
    private function run($spec)
    {
        $response = (new Backend())->configdpRun('hostguard query', $spec);
        $data = json_decode((string)$response, true);
        return is_array($data) ? $data : ['status' => 'error', 'message' => trim((string)$response)];
    }

    /**
     * add a block condition: from now on outside sources matching it go into the virusprot table
     */
    public function addAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $type = (string)$this->request->getPost('type');
        $value = str_replace(' ', '_', (string)$this->request->getPost('value'));
        $target = (string)$this->request->getPost('target');
        $duration = (string)$this->request->getPost('duration');
        if (!in_array($type, ['attack', 'ids', 'src_limit']) || !preg_match('/^[A-Za-z0-9_:.*-]{1,100}$/D', $value) ||
            ($target !== '*' && ($type === 'src_limit' || filter_var($target, FILTER_VALIDATE_IP) === false)) ||
            !ctype_digit($duration)) {
            return ['status' => 'error', 'message' => gettext('Invalid condition.')];
        }
        return $this->run(['cond_add', 0, '-', implode('|', [$type, $value, $target, $duration])]);
    }

    /**
     * remove a block condition, the addresses only it held leave the table
     */
    public function delAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $id = (string)$this->request->getPost('id');
        if (!ctype_digit($id)) {
            return ['status' => 'error', 'message' => gettext('Invalid condition id.')];
        }
        return $this->run(['cond_del', 0, '-', $id]);
    }
}
