<?php

declare(strict_types=1);

namespace OAT\Bundle\Lti1p3Bundle\Security\User;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * @psalm-immutable
 *
 * @author Mathias Arlaud <mathias.arlaud@gmail.com>
 */
final class LtiUser implements UserInterface
{
    protected string $identifier = '';

    /**
     * @psalm-mutation-free
     */
    public function getUsername(): string
    {
        return '';
    }

    public function setIdentifier(string $identifier): void
    {
        $this->identifier = $identifier;
    }

    public function getUserIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * @psalm-mutation-free
     */
    public function getPassword(): ?string
    {
        return null;
    }

    /**
     * @psalm-mutation-free
     */
    public function getSalt(): ?string
    {
        return null;
    }

    /**
     * @psalm-mutation-free
     */
    public function getRoles(): array
    {
        return [];
    }

    /**
     * @psalm-mutation-free
     */
    public function eraseCredentials(): void
    {
        return;
    }
}
