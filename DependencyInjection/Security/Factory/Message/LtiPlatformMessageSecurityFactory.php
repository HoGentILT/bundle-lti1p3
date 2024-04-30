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
 * Copyright (c) 2020 (original work) Open Assessment Technologies SA;
 */

declare(strict_types=1);

namespace OAT\Bundle\Lti1p3Bundle\DependencyInjection\Security\Factory\Message;

use OAT\Bundle\Lti1p3Bundle\Security\Authentication\Authenticator\Message\LtiPlatformMessageAuthenticator;
use OAT\Library\Lti1p3Core\Message\Launch\Validator\Platform\PlatformLaunchValidatorInterface;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class LtiPlatformMessageSecurityFactory implements AuthenticatorFactoryInterface
{
    public function getPosition(): string
    {
        return 'pre_auth';
    }

    public function getPriority(): int
    {
        return 0;
    }

    public function getKey(): string
    {
        return 'lti1p3_message_platform';
    }

    public function createAuthenticator(ContainerBuilder $container, string $firewallName, array $config, string $userProviderId): string
    {
        $providerId = sprintf('security.authenticator.%s.%s', $this->getKey(), $firewallName);
        $providerDefinition = new Definition(LtiPlatformMessageAuthenticator::class);
        $providerDefinition
            ->setShared(false)
            ->setArguments(
                [
                    new Reference(PlatformLaunchValidatorInterface::class),
                    new Reference(HttpMessageFactoryInterface::class),
                    $config['types'] ?? []
                ]
            );
        $container->setDefinition($providerId, $providerDefinition);

        return $providerId;
    }

    public function addConfiguration(NodeDefinition $node): void
    {
        $node->children()->arrayNode('types')->scalarPrototype()->end();
    }
}
