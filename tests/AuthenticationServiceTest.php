<?php

namespace Mittwald\MStudio\Authentication;

use DateTime;
use Mittwald\ApiClient\Client\UntypedResponse;
use Mittwald\ApiClient\Error\UnexpectedResponseException;
use Mittwald\ApiClient\Generated\V2\Clients\User\AuthenticateWithAccessTokenRetrievalKey\AuthenticateWithAccessTokenRetrievalKeyOKResponse;
use Mittwald\ApiClient\Generated\V2\Clients\User\AuthenticateWithAccessTokenRetrievalKey\AuthenticateWithAccessTokenRetrievalKeyOKResponseBody;
use Mittwald\ApiClient\Generated\V2\Clients\User\RefreshSession\RefreshSessionOKResponse;
use Mittwald\ApiClient\Generated\V2\Clients\User\RefreshSession\RefreshSessionOKResponseBody;
use Mittwald\ApiClient\Generated\V2\Clients\User\UserClient;
use Mittwald\ApiClient\MittwaldAPIV2Client;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use function PHPUnit\Framework\any;
use function PHPUnit\Framework\assertThat;
use function PHPUnit\Framework\equalTo;
use function PHPUnit\Framework\once;

#[CoversClass(AuthenticationService::class)]
class AuthenticationServiceTest extends TestCase
{
    #[Test]
    public function authenticateUsesRetrievalKey(): void
    {
        $userID       = "USER_ID";
        $retrievalKey = base64_encode(random_bytes(16));
        $accessToken  = base64_encode(random_bytes(16));
        $refreshToken = base64_encode(random_bytes(16));
        $expiration = new DateTime("now + 3 days");

        $response = new AuthenticateWithAccessTokenRetrievalKeyOKResponse(
            new AuthenticateWithAccessTokenRetrievalKeyOKResponseBody(
                token: $accessToken,
                refreshToken: $refreshToken,
                expiresAt: $expiration,
            ),
        );

        $userClient = $this->getMockBuilder(UserClient::class)->getMock();
        $userClient->expects(once())->method('authenticateWithAccessTokenRetrievalKey')->willReturn($response);

        $client = $this
            ->getMockBuilder(MittwaldAPIV2Client::class)
            ->disableOriginalConstructor()
            ->getMock();
        $client
            ->expects(any())
            ->method('user')
            ->willReturn($userClient);

        $sut = new AuthenticationService($client, new NullLogger());
        $token = $sut->authenticate($userID, $retrievalKey);

        assertThat($token->getAccessToken(), equalTo($accessToken));
        assertThat($token->getRefreshToken(), equalTo($refreshToken));
        assertThat($token->getExpiresAt(), equalTo($expiration));
    }

    #[Test]
    public function throwsAuthenticationErrorOnUnexpectedResponse(): void
    {
        $userID       = "USER_ID";
        $retrievalKey = base64_encode(random_bytes(16));

        $userClient = $this->getMockBuilder(UserClient::class)->getMock();
        $userClient
            ->expects(once())
            ->method('authenticateWithAccessTokenRetrievalKey')
            ->willThrowException(new UnexpectedResponseException(new UntypedResponse("noope", new Response(403))));

        $client = $this
            ->getMockBuilder(MittwaldAPIV2Client::class)
            ->disableOriginalConstructor()
            ->getMock();
        $client
            ->expects(any())
            ->method('user')
            ->willReturn($userClient);

        $this->expectException(AuthenticationError::class);

        $sut = new AuthenticationService($client, new NullLogger());
        $sut->authenticate($userID, $retrievalKey);
    }

    #[Test]
    public function refreshRefreshesToken(): void
    {
        $accessToken  = base64_encode(random_bytes(16));
        $refreshToken = base64_encode(random_bytes(16));
        $expiration = new DateTime("now + 3 days");

        $token = new SSOToken(
            accessToken: $accessToken,
            refreshToken: $refreshToken,
            expiresAt: $expiration,
        );

        $newAccessToken  = base64_encode(random_bytes(16));
        $newRefreshToken = base64_encode(random_bytes(16));
        $newExpiration = new DateTime("now + 3 days");

        $response = new RefreshSessionOKResponse(
            new RefreshSessionOKResponseBody(
                token: $newAccessToken,
                refreshToken: $newRefreshToken,
                expiresAt: $newExpiration,
            ),
        );

        $userClient = $this->getMockBuilder(UserClient::class)->getMock();
        $userClient->expects(once())->method('refreshSession')->willReturn($response);

        $client = $this
            ->getMockBuilder(MittwaldAPIV2Client::class)
            ->disableOriginalConstructor()
            ->getMock();
        $client
            ->expects(any())
            ->method('user')
            ->willReturn($userClient);

        $sut = new AuthenticationService($client, new NullLogger());
        $newToken = $sut->refresh($token);

        assertThat($newToken->getAccessToken(), equalTo($newAccessToken));
        assertThat($newToken->getRefreshToken(), equalTo($newRefreshToken));
        assertThat($newToken->getExpiresAt(), equalTo($newExpiration));
    }
}