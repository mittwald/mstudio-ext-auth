<?php

namespace Mittwald\MStudio\Authentication;

use DateTime;

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