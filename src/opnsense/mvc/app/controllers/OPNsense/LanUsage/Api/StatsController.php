<?php

/*
 * Copyright (C) 2026 Onur Berkay <onurberkay@sakla.app>
 * All rights reserved. (BSD 2-Clause, see LICENSE)
 */

namespace OPNsense\LanUsage\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Read-only statistics plus the on-demand service test.
 * All data comes from the collector database via configd (lanusage query / probe).
 */
class StatsController extends ApiControllerBase
{
    private function query($command, $extra = null)
    {
        $hours = (int)$this->request->get('hours');
        $hours = $hours > 0 ? min($hours, 24 * 366) : 24;
        $ip = (string)$this->request->get('ip');
        $ip = filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : '-';
        if ($extra === null) {
            $extra = (string)$this->request->get('dir');
            $extra = in_array($extra, ['in', 'out']) ? $extra : '-';
        }

        $response = (new Backend())->configdpRun('lanusage query', [$command, $hours, $ip, $extra]);
        $data = json_decode((string)$response, true);
        if (!is_array($data)) {
            return ['status' => 'error', 'message' => trim((string)$response)];
        }
        return $data;
    }

    public function summaryAction()
    {
        return $this->query('summary');
    }

    public function hostsAction()
    {
        return $this->query('hosts');
    }

    public function portsAction()
    {
        return $this->query('ports');
    }

    public function flowsAction()
    {
        return $this->query('flows');
    }

    public function servicesAction()
    {
        return $this->query('services');
    }

    public function alertsAction()
    {
        return $this->query('alerts', $this->request->get('which') === 'open' ? 'open' : 'all');
    }

    public function lateralAction()
    {
        return $this->query('lateral');
    }

    public function l2Action()
    {
        return $this->query('l2');
    }

    public function limitsAction()
    {
        return $this->query('limits');
    }

    public function blockedAction()
    {
        return $this->query('blocked');
    }

    public function statusAction()
    {
        return $this->query('status');
    }

    /**
     * acknowledge one alert (id) or all open alerts (id = all, optionally limited to ip)
     */
    public function ackAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $id = (string)$this->request->getPost('id');
        if ($id !== 'all' && !ctype_digit($id)) {
            return ['status' => 'error', 'message' => gettext('Invalid alert id.')];
        }
        $ip = (string)$this->request->getPost('ip');
        $ip = filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : '-';
        $response = (new Backend())->configdpRun('lanusage query', ['ack', 0, $ip, $id]);
        $data = json_decode((string)$response, true);
        return is_array($data) ? $data : ['status' => 'error', 'message' => trim((string)$response)];
    }

    public function probeAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $ip = (string)$this->request->getPost('ip');
        $port = (int)$this->request->getPost('port');
        $proto = (string)$this->request->getPost('proto');
        if (filter_var($ip, FILTER_VALIDATE_IP) === false || $port < 1 || $port > 65535 ||
            !in_array($proto, ['tcp', 'udp'])) {
            return ['status' => 'error', 'message' => gettext('Invalid address, port or protocol.')];
        }
        $response = (new Backend())->configdpRun('lanusage probe', [$ip, $port, $proto]);
        $data = json_decode((string)$response, true);
        return is_array($data) ? $data : ['status' => 'error', 'message' => trim((string)$response)];
    }

    public function clearAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $response = (new Backend())->configdRun('lanusage clear');
        $data = json_decode((string)$response, true);
        return is_array($data) ? $data : ['status' => 'error', 'message' => trim((string)$response)];
    }
}
