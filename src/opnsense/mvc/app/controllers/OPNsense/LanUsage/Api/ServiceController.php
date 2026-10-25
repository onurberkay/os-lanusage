<?php

/*
 * Copyright (C) 2026 Onur Berkay <onurberkay@sakla.app>
 * All rights reserved. (BSD 2-Clause, see LICENSE)
 */

namespace OPNsense\LanUsage\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\LanUsage\General';
    protected static $internalServiceTemplate = 'OPNsense/LanUsage';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceName = 'lanusage';
}
