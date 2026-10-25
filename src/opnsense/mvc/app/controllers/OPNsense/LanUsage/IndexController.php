<?php

/*
 * Copyright (C) 2026 Onur Berkay <onurberkay@sakla.app>
 * All rights reserved. (BSD 2-Clause, see LICENSE)
 */

namespace OPNsense\LanUsage;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/LanUsage/index');
    }
}
