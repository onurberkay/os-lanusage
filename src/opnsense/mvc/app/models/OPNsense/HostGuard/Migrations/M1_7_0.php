<?php

/*
 * Copyright (C) 2026 Onur Berkay <onurberkay@sakla.app>
 * All rights reserved. (BSD 2-Clause, see LICENSE)
 *
 * os-lanusage -> os-hostguard: take over the settings of the earlier plugin
 * (OPNsense/lanusage/general in config.xml). Only while the HostGuard section does not exist yet;
 * the old section is kept, only disabled (enabled = 0).
 */

namespace OPNsense\HostGuard\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\Core\Config;

class M1_7_0 extends BaseModelMigration
{
    public function run($model)
    {
        $root = Config::getInstance()->object();
        $previous = [];
        // settings saved in the GUI meanwhile are never replaced by the old ones
        if (isset($root->OPNsense->lanusage->general) && !isset($root->OPNsense->hostguard)) {
            foreach ($root->OPNsense->lanusage->general->children() as $name => $value) {
                // every item of the model is a plain field, no containers
                $node = $model->getNodeByReference($name);
                if ($node !== null) {
                    $previous[$name] = (string)$node;
                    $node->setValue((string)$value);
                }
            }
            // an os-lanusage package still installed must not start its collector again at the next boot
            // (its template is reloaded then); run_migrations saves the whole configuration
            $root->OPNsense->lanusage->general->enabled = '0';
        }
        // one value the model does not accept must not make the whole section fail to save:
        // first a taken over one goes back to the default (e.g. an interface removed since), then a default
        // that is not valid here either (e.g. "lan" on a box without one) is left empty when not required
        foreach ([true, false] as $restore) {
            foreach ($model->performValidation() as $message) {
                $name = substr(strrchr('.' . $message->getField(), '.'), 1);
                $node = $model->getNodeByReference($name);
                if ($node === null) {
                    continue;
                }
                if ($restore && isset($previous[$name])) {
                    $node->setValue($previous[$name]);
                } elseif (!$restore && !$node->isRequired()) {
                    $node->setValue('');
                }
            }
        }
        parent::run($model);
    }
}
