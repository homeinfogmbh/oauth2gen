"""Handling of refresh tokens."""

from typing import Iterable, Optional, Type

from authlib.oauth2.rfc6749 import grants
from peewee import Model

from oauth2gen.mixins import OAuth2TokenMixin


__all__ = ['RefreshTokenGrant']


class RefreshTokenGrant(grants.RefreshTokenGrant):
    """Handles refresh token grants."""

    def __init_subclass__(
            cls, *,
            token: Type[OAuth2TokenMixin],
            auth_methods: Iterable[str] = ('client_secret_post',),
            include_new_refresh_token: bool = True,
            **kwargs
    ):
        """Sets the token model."""
        super().__init_subclass__(**kwargs)
        cls.TOKEN_MODEL = token
        cls.CLIENT_AUTH_METHODS = list(auth_methods)
        cls.INCLUDE_NEW_REFRESH_TOKEN = include_new_refresh_token

    def authenticate_refresh_token(
            self, refresh_token: str
    ) -> Optional[OAuth2TokenMixin]:
        """Authenticates the refresh token."""
        try:
            refresh_token = self.TOKEN_MODEL.get(
                self.TOKEN_MODEL.refresh_token == refresh_token
            )
        except self.TOKEN_MODEL.DoesNotExist:
            return None

        if refresh_token.revoked:
            return None

        return refresh_token

    def authenticate_user(
            self, credential: OAuth2TokenMixin
    ) -> Optional[Model]:
        """Authenticates the user."""
        if credential.is_valid():
            return credential.user

        return None

    def revoke_old_credential(self, credential: OAuth2TokenMixin) -> None:
        """Revokes the credential."""
        credential.revoked = True
        credential.save()
