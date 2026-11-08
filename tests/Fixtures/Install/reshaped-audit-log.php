<?php

declare(strict_types = 1);

/*
 * An audit-log configuration file reshaped so it no longer holds the defaults
 * `iam:install` writes over: the excluded guards and the refusal of codes no
 * definition registers are each written out as values of their own.
 */

return [
    'definitions' => [
        'require_registered' => false,
    ],
    'capture' => [
        'laravel' => [
            'except_guards' => ['web'],
        ],
    ],
];
