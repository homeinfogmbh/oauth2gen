"""OAuth 2.0 authorization server."""

from functools import partial
from typing import Any, Iterable, Optional, Type

from authlib.integrations import flask_oauth2
from authlib.oauth2.rfc6749 import TokenEndpoint
from authlib.oauth2.rfc6749.grants import BaseGrant
from flask import Flask, Response
from peewee import Model

from wsgilib import get_int


__all__ = ['AuthorizationServer']


class AuthorizationServer(flask_oauth2.AuthorizationServer):
    """Subclass of the original flask authorization server."""

    def __init_subclass__(
            cls, *,
            client: Type[Model],
            token: Type[Model],
            grants: Iterable[BaseGrant],
            token_introspection_endpoint: TokenEndpoint,
            token_revocation_endpoint: TokenEndpoint,
            **kwargs
    ):
        """Sets the token an user models."""
        super().__init_subclass__(**kwargs)
        cls.CLIENT_MODEL = client
        cls.TOKEN_MODEL = token
        cls.GRANT_TYPES = list(grants)
        cls.TOKEN_INTROSPECTION_ENDPOINT = token_introspection_endpoint
        cls.TOKEN_REVOCATION_ENDPOINT = token_revocation_endpoint

    def __init__(self, application: Flask):
        super().__init__(
            application,
            query_client=partial(query_client, self.CLIENT_MODEL),
            save_token=partial(save_token, self.TOKEN_MODEL)
        )

        for grant in self.GRANT_TYPES:
            self.register_grant(grant)

        self.register_endpoint(self.TOKEN_INTROSPECTION_ENDPOINT)
        self.register_endpoint(self.TOKEN_REVOCATION_ENDPOINT)

    def create_authorization_response(
            self, request: Optional[Any] = None, grant_user: Any = None
    ) -> Response:
        """Enhanced authorization response generation."""
        response = super().create_authorization_response(
            request=request, grant_user=grant_user
        )
        response.status_code = get_int('redirect_status_code', 302)
        return response

    def revoke_token(self) -> Response:
        """Revoke a token."""
        return self.create_endpoint_response(
            self.TOKEN_REVOCATION_ENDPOINT.ENDPOINT_NAME
        )

    def introspect_token(self) -> Response:
        """Introspects a token."""
        return self.create_endpoint_response(
            self.TOKEN_INTROSPECTION_ENDPOINT.ENDPOINT_NAME
        )


def query_client(
        client: Type[Model], client_id: str
) -> Optional[Model]:
    """Returns a client by its ID."""

    try:
        return client.get(client.client_id == client_id)
    except client.DoesNotExist:
        return None


def save_token(
        token: Type[Model], token_data: dict, request: Any
) -> None:
    """Stores the respective token."""

    if request.user:
        user_id = request.user.id
    else:
        user_id = request.client.user_id

    token(
        client_id=request.client.client_id, user_id=user_id, **token_data
    ).save()
