<?php

declare(strict_types=1);

namespace OAT\Bundle\Lti1p3Bundle\Security\Authentication;


use OAT\Library\Lti1p3Core\Util\Result\ResultInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\BadgeInterface;

class LtiBadge implements BadgeInterface
{
    private ResultInterface $result;

    public function __construct(ResultInterface $result)
    {
        $this->result = $result;
    }

    public function getResult(): ResultInterface
    {
        return $this->result;
    }

    public function isResolved(): bool
    {
        return !$this->result->hasError();
    }
}
