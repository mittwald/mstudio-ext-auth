<?php

namespace Mittwald\MStudio\Authentication;

use GuzzleHttp\Exception\GuzzleException;
use InvalidArgumentException;
use Mittwald\ApiClient\Error\UnexpectedResponseException;
use Mittwald\ApiClient\Generated\V2\Clients\User\AuthenticateWithAccessTokenRetrievalKey\AuthenticateWithAccessTokenRetrievalKeyRequest;
use Mittwald\ApiClient\Generated\V2\Clients\User\AuthenticateWithAccessTokenRetrievalKey\AuthenticateWithAccessTokenRetrievalKeyRequestBody;
use Mittwald\ApiClient\Generated\V2\Clients\User\RefreshSession\RefreshSessionRequest;
use Mittwald\ApiClient\Generated\V2\Clients\User\RefreshSession\RefreshSessionRequestBody;
use Mittwald\ApiClient\MittwaldAPIV2Client;
use Psr\Log\LoggerInterface;
use SensitiveParameter;

/**
 * Authentication service that implements the ATReK authentication mechanism
 * as documented in [1].
 *
 * [1]: https://developer.mittwald.de/docs/v2/contribution/overview/concepts/authentication/
 */
class AuthenticationService
{
    private MittwaldAPIV2Client $client;
    private LoggerInterface $logger;

    public function __construct(MittwaldAPIV2Client $client, LoggerInterface $logger)
    {
        $this->client = $client;
        $this->logger = $logger;
    }

    /**
     * Exchanges a token retrieval key for an actual API token.
     *
     * @param string $userId ID of the user to authenticate
     * @param string $tokenRetrievalKey The ATReK (usually passed as a request parameter during the SSO flow)
     * @return SSOToken An object encapsulating the access token and the associated refresh token.
     * @throws AuthenticationError
     * @throws GuzzleException
     */
    public function authenticate(string $userId, #[SensitiveParameter] string $tokenRetrievalKey): SSOToken
    {
        $authRequest = new AuthenticateWithAccessTokenRetrievalKeyRequest(
            new AuthenticateWithAccessTokenRetrievalKeyRequestBody(
                accessTokenRetrievalKey: $tokenRetrievalKey,
                userId: $userId,
            )
        );

        $this->logger->debug('authenticating user with userId {userId}', ['userId' => $userId]);

        try {
            $authResponse = $this->client->user()->authenticateWithAccessTokenRetrievalKey($authRequest)->getBody();

            return new SSOToken(
                accessToken: $authResponse->getToken(),
                refreshToken: $authResponse->getRefreshToken(),
                expiresAt: $authResponse->getExpiresAt(),
            );
        } catch (UnexpectedResponseException $error) {
            throw new AuthenticationError('Authentication failed: ' . $error->response->getBody()->getContents(), previous: $error);
        }
    }

    /**
     * Refreshes an access token.
     *
     * Uses the refresh token stored in an SSOToken object to exchange the
     * actual access token with a fresh one.
     *
     * @param SSOToken $token The old token object
     * @return SSOToken An updated token object with new tokens
     * @throws AuthenticationError
     * @throws GuzzleException
     */
    public function refresh(SSOToken $token): SSOToken
    {
        $refreshToken = $token->getRefreshToken();
        if (is_null($refreshToken)) {
            throw new InvalidArgumentException("token did not contain a refresh token");
        }

        $refreshRequest = new RefreshSessionRequest(
            new RefreshSessionRequestBody(
                refreshToken: $refreshToken,
            )
        );

        try {
            $refreshResponse = $this->client->user()->refreshSession($refreshRequest)->getBody();

            return new SSOToken(
                accessToken: $refreshResponse->getToken(),
                refreshToken: $refreshResponse->getRefreshToken(),
                expiresAt: $refreshResponse->getExpiresAt(),
            );
        } catch (UnexpectedResponseException $error) {
            throw new AuthenticationError('refresh failed', previous: $error);
        }
    }

}