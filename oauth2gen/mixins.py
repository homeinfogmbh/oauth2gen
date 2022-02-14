"""ORM model mixins for OAuth 2.0 providers."""

from datetime import datetime, timedelta
from typing import Any, Optional

from argon2.exceptions import VerifyMismatchError
from authlib.oauth2.rfc6749 import ClientMixin
from authlib.oauth2.rfc6749 import TokenMixin
from authlib.oauth2.rfc6749 import AuthorizationCodeMixin
from authlib.oauth2.rfc6749.util import scope_to_list, list_to_scope


__all__ = [
    'OAuth2ClientMixin',
    'OAuth2TokenMixin',
    'OAuth2AuthorizationCodeMixin'
]


class OAuth2ClientMixin(ClientMixin):
    """An OAuth 2.0 client mixin for peewee models."""

    @property
    def client_info(self) -> dict[str, Any]:
        """Implementation for Client Info in OAuth 2.0 Dynamic Client
        Registration Protocol via `Section 3.2.1`.

        `Section 3.2.1`: https://tools.ietf.org/html/rfc7591#section-3.2.1
        """
        return {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'client_id_issued_at': self.client_id_issued_at,
            'client_secret_expires_at': self.client_secret_expires_at
        }

    def get_client_id(self):
        """Returns the client's ID."""
        return self.client_id

    def get_default_redirect_uri(self) -> Optional[str]:
        """Returns the default redirect URI."""
        try:
            redirect_uri, *_ = self.redirect_uris
        except ValueError:
            return None

        return redirect_uri

    def get_allowed_scope(self, scope: str) -> str:
        """Returns the allowed scope."""
        if not scope:
            return ''

        allowed = {scope.scope for scope in self.scopes}
        scopes = scope_to_list(scope)
        return list_to_scope([scope for scope in scopes if scope in allowed])

    def check_redirect_uri(self, redirect_uri: str) -> bool:
        """Checks the redirect URI."""
        return redirect_uri in {uri.uri for uri in self.redirect_uris}

    def has_client_secret(self) -> bool:
        """Checks if the client's secret is set."""
        return self.client_secret is not None

    def check_client_secret(self, client_secret: str) -> bool:
        """Verifies the client's secret."""
        # pylint: disable=E1101
        try:
            return self.client_secret.verify(client_secret)
        except VerifyMismatchError:
            return False

    def check_token_endpoint_auth_method(self, method) -> bool:
        return self.token_endpoint_auth_method == method

    def check_response_type(self, response_type: str) -> bool:
        """Verifies the response type."""
        return response_type in {typ.type for typ in self.response_types}

    def check_grant_type(self, grant_type: str) -> bool:
        """Verifies the grant type."""
        return grant_type in {typ.type for typ in self.grant_types}


class OAuth2TokenMixin(TokenMixin):
    """Mixin for OAuth 2.0 tokens."""

    @property
    def expires_at(self) -> datetime:
        """Returns the datetime when the token expires."""
        return self.issued_at + timedelta(seconds=self.expires_in)

    def get_client_id(self) -> Optional[str]:
        """Returns the client ID."""
        return self.client_id

    def get_expires_at(self) -> float:
        """Returns the timestamp when the token expires."""
        return self.expires_at.timestamp()

    def check_client(self, client: OAuth2ClientMixin) -> bool:
        """Returns the client ID."""
        return client.client_id == self.client_id

    def get_scope(self) -> str:
        """Returns the scope."""
        return self.scope

    def get_expires_in(self) -> int:
        """Returns the amount of microseconds the token expires in."""
        return self.expires_in

    def is_expired(self) -> bool:
        """Determines whether the token is expired."""
        return self.expires_at <= datetime.now()

    def is_revoked(self) -> bool:
        """Determines whether the token is revoked."""
        return self.revoked


class OAuth2AuthorizationCodeMixin(AuthorizationCodeMixin):
    """Mixin for OAuth 2.0 authorization codes."""

    def is_expired(self) -> bool:
        """Determines whether the authorization code is expired."""
        return self.auth_time + timedelta(seconds=300) < datetime.now()

    def get_redirect_uri(self) -> str:
        """Returns a redirect URI."""
        return self.redirect_uri

    def get_scope(self) -> str:
        """Returns the scope."""
        return self.scope

    def get_auth_time(self) -> datetime:
        """Returns the authentication time."""
        return self.auth_time

    def get_nonce(self) -> str:
        """Returns the nonce."""
        return self.nonce
