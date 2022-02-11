"""OAuth2 authorization server."""

from typing import Iterable, Iterator, Type

from authlib.oauth2.rfc6749.grants import BaseGrant, ImplicitGrant

from oauth2gen.oauth2.authorization_code_grant import AuthorizationCodeGrant
from oauth2gen.oauth2.authorization_server import AuthorizationServer
from oauth2gen.oauth2.bearer_token_validator import BearerTokenValidator
from oauth2gen.oauth2.introspection_endpoint import TokenIntrospectionEndpoint
from oauth2gen.oauth2.refresh_token_grant import RefreshTokenGrant
from oauth2gen.oauth2.revocation_endpoint import TokenRevocationEndpoint
from oauth2gen.orm import OAuth2Models


__all__ = ['BearerTokenValidator', 'create_authorization_server']


def create_authorization_server(
        models: OAuth2Models,
        url: str,
        *,
        auth_methods: Iterable[str] = ('client_secret_post',),
        implicit_grant: bool = True,
        include_new_refresh_token: bool = True
) -> Type[AuthorizationServer]:
    """Creates the authorization server."""

    class _AuthorizationServer(
        AuthorizationServer,
        client=models.client,
        token=models.token,
        grants=get_grants(
            models,
            url,
            auth_methods=auth_methods,
            implicit_grant=implicit_grant,
            include_new_refresh_token=include_new_refresh_token
        )
    ):
        pass

    return _AuthorizationServer


def get_grants(
        models: OAuth2Models,
        url: str,
        *,
        auth_methods: Iterable[str] = ('client_secret_post',),
        implicit_grant: bool = True,
        include_new_refresh_token: bool = True
) -> Iterator[BaseGrant]:
    """Yields the default grants."""

    if implicit_grant:
        yield ImplicitGrant

    class _AuthorizationCodeGrant(
        AuthorizationCodeGrant,
        authorization_code=models.authorization_code,
        user=models.user,
        auth_methods=auth_methods
    ):
        pass

    yield _AuthorizationCodeGrant

    class _RefreshTokenGrant(
        RefreshTokenGrant,
        token=models.token,
        auth_methods=auth_methods,
        include_new_refresh_token=include_new_refresh_token
    ):
        pass

    yield _RefreshTokenGrant

    class _TokenRevocationEndpoint(
        TokenRevocationEndpoint,
        token=models.token,
        auth_methods=auth_methods
    ):
        pass

    yield _TokenRevocationEndpoint

    class _TokenIntrospectionEndpoint(
        TokenIntrospectionEndpoint,
        token=models.token,
        url=url,
        auth_methods=auth_methods
    ):
        pass

    yield _TokenIntrospectionEndpoint
