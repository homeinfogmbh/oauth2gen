"""Token introspection endpoint."""

from typing import Any, Iterable, Optional, Type

from authlib.oauth2.rfc7662 import IntrospectionEndpoint

from oauth2gen.mixins import OAuth2ClientMixin, OAuth2TokenMixin


__all__ = ["TokenIntrospectionEndpoint"]


class TokenIntrospectionEndpoint(IntrospectionEndpoint):
    """Introspection of bearer tokens."""

    def __init_subclass__(
        cls,
        *,
        token: Type[OAuth2TokenMixin],
        url: str,
        auth_methods: Iterable[str] = ("client_secret_post",),
        **kwargs
    ):
        """Sets the token model."""
        super().__init_subclass__(**kwargs)
        cls.TOKEN_MODEL = token
        cls.URL = url
        cls.TOKEN_ENDPOINT_AUTH_METHODS = list(auth_methods)

    def query_token(
        self, token: str, token_type_hint: str, client: OAuth2ClientMixin
    ) -> Optional[OAuth2TokenMixin]:
        """Returns the respective token."""
        try:
            token = self.TOKEN_MODEL.get(
                get_token_condition(self.TOKEN_MODEL, token, token_type_hint)
            )
        except self.TOKEN_MODEL.DoesNotExist:
            return None

        if token.client_id == client.client_id:
            return token

        return None

    def introspect_token(self, token: OAuth2TokenMixin) -> dict[str, Any]:
        """Returns a JSON-ish dict of the token."""
        return {
            "active": True,
            "client_id": token.client_id,
            "token_type": token.token_type,
            "username": token.user.uuid.hex,
            "scope": token.get_scope(),
            "sub": token.user.uuid.hex,
            "aud": token.client_id,
            "iss": self.URL,
            "exp": token.expires_at,
            "iat": token.issued_at,
        }


def get_token_condition(
    model: Type[OAuth2TokenMixin], token: str, token_type_hint: str
) -> OAuth2TokenMixin:
    """Returns the respective token."""

    if token_type_hint == "access_token":
        return model.access_token == token

    if token_type_hint == "refresh_token":
        return model.refresh_token == token

    return (model.access_token == token) | (model.refresh_token == token)
