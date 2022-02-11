"""Toaken revication endpoint."""

from typing import Iterable, Optional, Type

from authlib.oauth2.rfc7009 import RevocationEndpoint
from peewee import Expression

from oauth2gen.mixins import OAuth2ClientMixin, OAuth2TokenMixin


__all__ = ['TokenRevocationEndpoint']


class TokenRevocationEndpoint(RevocationEndpoint):
    """A Token revocation endpoint."""

    def __init_subclass__(
            cls,
            token: Type[OAuth2TokenMixin],
            auth_methods: Iterable[str] = ('client_secret_post',),
            **kwargs
    ):
        """Sets the token model."""
        super().__init_subclass__(**kwargs)
        cls.TOKEN_MODEL = token
        cls.CLIENT_AUTH_METHODS = list(auth_methods)

    def query_token(
            self, token: str, token_type_hint: str, client: OAuth2TokenMixin
    ) -> Optional[OAuth2TokenMixin]:
        """Queries a token from the database."""
        try:
            return self.TOKEN_MODEL.get(get_token_condition(
                self.TOKEN_MODEL, client, token, token_type_hint
            ))
        except self.TOKEN_MODEL.DoesNotExist:
            return None

    def revoke_token(self, token: OAuth2ClientMixin) -> None:
        """Revokes the respective token."""
        token.revoked = True
        token.save()


def get_token_condition(
        model: Type[OAuth2TokenMixin],
        client: OAuth2ClientMixin,
        token: str,
        token_type_hint: str
) -> Expression:

    condition = model.client_id == client.client_id
    condition_access_token = model.access_token == token
    condition_refresh_token = model.refresh_token == token

    if token_type_hint == 'access_token':
        return condition & condition_access_token

    if token_type_hint == 'refresh_token':
        return condition & condition_refresh_token

    return condition & (condition_access_token | condition_refresh_token)
