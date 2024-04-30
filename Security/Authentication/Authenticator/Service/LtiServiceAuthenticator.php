<?php

/**
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; under version 2
 * of the License (non-upgradable).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (c) 2021 (original work) Open Assessment Technologies SA;
 */

declare(strict_types=1);

namespace OAT\Bundle\Lti1p3Bundle\Security\Authentication\Authenticator\Service;

use OAT\Bundle\Lti1p3Bundle\Security\Authentication\LtiBadge;
use OAT\Bundle\Lti1p3Bundle\Security\Authentication\LtiPassport;
use OAT\Bundle\Lti1p3Bundle\Security\Authentication\Token\Service\LtiServiceSecurityToken;
use OAT\Bundle\Lti1p3Bundle\Security\User\LtiUser;
use OAT\Library\Lti1p3Core\Exception\LtiException;
use OAT\Library\Lti1p3Core\Message\Launch\Validator\Platform\PlatformLaunchValidatorInterface;
use OAT\Library\Lti1p3Core\Security\OAuth2\Validator\RequestAccessTokenValidatorInterface;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Throwable;

class LtiServiceAuthenticator extends AbstractLtiAuthenticator
{
    private RequestAccessTokenValidatorInterface $validator;
    private HttpMessageFactoryInterface $factory;

    /** string[] */
    private array $scopes;

    public function __construct(PlatformLaunchValidatorInterface $validator, HttpMessageFactoryInterface $factory, array $scopes = [])
    {
        $this->validator = $validator;
        $this->factory = $factory;
        $this->types = $scopes;
    }

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization');
    }

    public function authenticate(Request $request): Passport
    {
        try {
            $validationResult = $this->validator->validate(
                $this->factory->createRequest($request),
                $this->scopes
            );

            if ($validationResult->hasError()) {
                throw new LtiException($validationResult->getError());
            }

            $userLoader = function (string $userIdentifier): UserInterface {
                return new LtiUser();
            };

            return new LtiPassport(new UserBadge('', $userLoader), new LtiBadge($validationResult));

        } catch (Throwable $exception) {
            throw new AuthenticationException(
                sprintf('LTI service request authentication failed: %s', $exception->getMessage()),
                (int) $exception->getCode(),
                $exception
            );
        }
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        if (!$passport instanceof LtiPassport)
        {
            throw new LogicException(sprintf('Provided passport must be a %s instance', LtiPassport::class));
        }

        return new LtiServiceSecurityToken($passport->getLtiBadge()->getResult());
    }
}
