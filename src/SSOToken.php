<?php

namespace Mittwald\MStudio\Authentication;

use DateTime;
use Doctrine\ORM\Mapping\Column;
use Doctrine\ORM\Mapping\Entity;
use Doctrine\ORM\Mapping\Id;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

readonly class SSOToken
{
    private string $accessToken;

    private ?string $refreshToken;

    private ?DateTime $expiresAt;

    public function __construct(string $accessToken, ?string $refreshToken = null, ?DateTime $expiresAt = null)
    {
        $this->accessToken = $accessToken;
        $this->refreshToken = $refreshToken;
        $this->expiresAt = $expiresAt;
    }

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }

    public function getExpiresAt(): ?DateTime
    {
        return $this->expiresAt;
    }

}