"""Validation of bearer tokens."""

from typing import Any, Optional, Type

from authlib.oauth2 import rfc6750
from peewee import Model

from oauth2gen.mixins import OAuth2TokenMixin


__all__ = ["BearerTokenValidator"]


class BearerTokenValidator(rfc6750.BearerTokenValidator):
    """Validates bearer tokens."""

    def __init__(
        self, token_model: Type[OAuth2TokenMixin], realm: Optional[str] = None
    ):
        """Sets the token model."""
        super().__init__(realm=realm)
        self.token_model = token_model

    def authenticate_token(self, token_string: str) -> Optional[OAuth2TokenMixin]:
        """Authenticates a token."""
        try:
            return self.token_model.get(self.token_model.access_token == token_string)
        except self.token_model.DoesNotExist:
            return None

    def request_invalid(self, request: Any) -> bool:
        """Determines whether the request is invalid."""
        return False

    def token_revoked(self, token: Model) -> bool:
        """Determines whether the token is revoked."""
        return token.revoked
