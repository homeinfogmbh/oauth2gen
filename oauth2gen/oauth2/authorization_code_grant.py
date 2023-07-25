"""Authorization code grants."""

from typing import Any, Iterable, Optional, Type

from authlib.oauth2.rfc6749 import grants
from peewee import Model

from oauth2gen.mixins import OAuth2ClientMixin


__all__ = ["AuthorizationCodeGrant"]


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    """Handles authorization code grants."""

    def __init_subclass__(
        cls,
        *,
        authorization_code: Type[Model],
        user: Type[Model],
        auth_methods: Iterable[str] = ("client_secret_post",),
        **kwargs
    ):
        """Sets the respective models."""
        super().__init_subclass__(**kwargs)
        cls.AUTHORIZATION_CODE_MODEL = authorization_code
        cls.USER_MODEL = user
        cls.TOKEN_ENDPOINT_AUTH_METHODS = list(auth_methods)

    def save_authorization_code(self, code: str, request: Any) -> None:
        """Saves an authorization code."""
        self.AUTHORIZATION_CODE_MODEL(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
        ).save()

    def query_authorization_code(
        self, code: str, client: OAuth2ClientMixin
    ) -> Optional[Type[Model]]:
        """Returns the authorization code."""
        try:
            return (
                self.AUTHORIZATION_CODE_MODEL.select(
                    self.AUTHORIZATION_CODE_MODEL, self.USER_MODEL
                )
                .join(self.USER_MODEL)
                .where(
                    (self.AUTHORIZATION_CODE_MODEL.code == code)
                    & (self.AUTHORIZATION_CODE_MODEL.client_id == client.client_id)
                )
                .get()
            )
        except self.AUTHORIZATION_CODE_MODEL.DoesNotExist:
            return None

    def delete_authorization_code(self, authorization_code: Model) -> None:
        """Deletes the respective authorization code."""
        authorization_code.delete_instance()

    def authenticate_user(self, authorization_code: Model) -> Optional[Model]:
        """Authenticates a user."""
        if authorization_code.is_expired():
            return None

        return authorization_code.user
