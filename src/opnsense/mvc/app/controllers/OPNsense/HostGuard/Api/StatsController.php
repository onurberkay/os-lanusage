<?php

/*
 * Copyright (C) 2026 Onur Berkay <onurberkay@sakla.app>
 * All rights reserved. (BSD 2-Clause, see LICENSE)
 */

namespace OPNsense\HostGuard\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Read-only statistics plus the on-demand service test.
 * All data comes from the collector database via configd (hostguard query / probe).
 */
class StatsController extends ApiControllerBase
{
    /**
     * host filter: '-' for none; null for an invalid one (never silently widened to every host)
     */
    private function hostFilter($ip)
    {
        $ip = trim((string)$ip);
        if ($ip === '' || $ip === '-') {
            return '-';
        }
        return filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : null;
    }

    private function query($command, $extra = null)
    {
        $hours = (int)$this->request->get('hours');
        $hours = $hours > 0 ? min($hours, 24 * 366) : 24;
        $ip = $this->hostFilter($this->request->get('ip'));
        if ($ip === null) {
            return ['status' => 'error', 'message' => gettext('Invalid host address.')];
        }
        if ($extra === null) {
            $extra = (string)$this->request->get('dir');
            $extra = in_array($extra, ['in', 'out']) ? $extra : '-';
        }

        $response = (new Backend())->configdpRun('hostguard query', [$command, $hours, $ip, $extra]);
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

    public function attacksAction()
    {
        // a group the Blocked / Limits tabs link to: "t=<LAN host>|<proto/port>;" or "l=<limit>@<rule>;"
        $group = strtolower((string)$this->request->get('group'));
        if (!preg_match('/^(t=[0-9a-f:.]+\|[a-z0-9\/-]+|l=[a-z-]+@[0-9]+);$/D', $group)) {
            $group = '-';
        }
        return $this->query('attacks', $group);
    }

    public function conditionsAction()
    {
        return $this->query('conditions');
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
        $ip = $this->hostFilter($this->request->getPost('ip'));
        if ($ip === null) {
            return ['status' => 'error', 'message' => gettext('Invalid host address.')];
        }
        $response = (new Backend())->configdpRun('hostguard query', ['ack', 0, $ip, $id]);
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
        $response = (new Backend())->configdpRun('hostguard probe', [$ip, $port, $proto]);
        $data = json_decode((string)$response, true);
        return is_array($data) ? $data : ['status' => 'error', 'message' => trim((string)$response)];
    }
}
