<?php

namespace App\Enum;

enum RoleEnum: string
{
    const ADMIN = 'admin';
    const AMLAK = 'amlak';
    const MONSHI = 'monshi';
    const MOSHAVER = 'moshaver';

    public static function getValues(): array
    {
        return [
            self::ADMIN,
            self::AMLAK,
            self::MONSHI,
            self::MOSHAVER,
        ];
    }
}
