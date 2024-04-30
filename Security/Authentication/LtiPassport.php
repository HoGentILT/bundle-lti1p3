<?php

declare(strict_types=1);

namespace OAT\Bundle\Lti1p3Bundle\Security\Authentication;

use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class LtiPassport extends SelfValidatingPassport
{
    public function __construct(UserBadge $userBadge, LtiBadge $ltiBadge)
    {
        parent::__construct($userBadge, [$ltiBadge]);
    }

    public function getLtiBadge(): LtiBadge
    {
        return $this->getBadge(LtiBadge::class);
    }
}
