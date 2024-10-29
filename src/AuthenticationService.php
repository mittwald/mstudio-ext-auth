<?php

namespace Mittwald\MStudio\Authentication;

use GuzzleHttp\Exception\GuzzleException;
use Mittwald\ApiClient\Error\UnexpectedResponseException;
use Mittwald\ApiClient\Generated\V2\Clients\User\AuthenticateWithAccessTokenRetrievalKey\AuthenticateWithAccessTokenRetrievalKeyRequest;
use Mittwald\ApiClient\Generated\V2\Clients\User\AuthenticateWithAccessTokenRetrievalKey\AuthenticateWithAccessTokenRetrievalKeyRequestBody;
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

}