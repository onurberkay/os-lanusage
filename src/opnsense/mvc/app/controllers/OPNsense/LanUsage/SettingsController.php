<?php

/*
 * Copyright (C) 2026 Onur Berkay <onurberkay@sakla.app>
 * All rights reserved. (BSD 2-Clause, see LICENSE)
 */

namespace OPNsense\LanUsage;

class SettingsController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->generalForm = $this->getForm('general');
        $this->view->pick('OPNsense/LanUsage/settings');
    }
}
