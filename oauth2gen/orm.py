"""ORM model generation for OAuth2 providers."""

from datetime import datetime
from typing import Any, NamedTuple, Optional, Type
from uuid import uuid4

from peewee import BooleanField
from peewee import CharField
from peewee import DateTimeField
from peewee import ForeignKeyField
from peewee import IntegerField
from peewee import Model
from peewee import TextField

from authlib.common.encoding import json_loads, json_dumps
from authlib.common.security import generate_token
from peeweeplus import Argon2Field, JSONTextField, Transaction

from oauth2gen.mixins import OAuth2ClientMixin
from oauth2gen.mixins import OAuth2TokenMixin
from oauth2gen.mixins import OAuth2AuthorizationCodeMixin


__all__ = ['OAuth2Models', 'create_models']


class OAuth2Models(NamedTuple):
    """Represents OAuth2 framework models."""

    user: Type[Model]
    client: Type[Model]
    redirect_uri: Type[Model]
    grant_type: Type[Model]
    response_type: Type[Model]
    scope: Type[Model]
    contact: Type[Model]
    jwks: Type[Model]
    token: Type[Model]
    authorization_code: Type[Model]


def create_models(
        user_model: Type[Model],
        config: dict[str, Any],
        *,
        base_model: Optional[Type[Model]] = None
) -> OAuth2Models:
    """Creates OAuth models for the given user model."""

    if base_model is None:
        base_model = user_model.__mro__[1]

    class Client(base_model, OAuth2ClientMixin):
        """An OAuth client."""

        user = ForeignKeyField(
            user_model, column_name='user', on_delete='CASCADE',
            lazy_load=False
        )
        client_id = CharField(48, default=lambda: uuid4().hex, index=True)
        client_secret = Argon2Field(null=True)
        client_id_issued_at = IntegerField(
            default=lambda: datetime.now().timestamp()
        )
        client_secret_expires_at = IntegerField(default=0)
        # Meta data.
        token_endpoint_auth_method = TextField(null=True)
        client_name = TextField(null=True)
        client_uri = TextField(null=True)
        logo_uri = TextField(null=True)
        tos_uri = TextField(null=True)
        policy_uri = TextField(null=True)
        jwks_uri = TextField(null=True)
        software_id = TextField(null=True)
        software_version = TextField(null=True)

        @classmethod
        def add(cls, user: user_model, secret: str) -> Transaction:
            """Adds a new client for the given user."""
            client = cls(
                user=user,
                token_endpoint_auth_method=config.get(
                    'token_endpoint_auth_method'
                )
            )
            client.client_secret = secret
            transaction = Transaction()
            transaction.add(client, primary=True)

            for uri in config.get('redirect_uris', []):
                transaction.add(RedirectURI(client=client, uri=uri))

            for typ in config.get('grant_types', []):
                transaction.add(GrantType(client=client, type=typ))

            for typ in config.get('response_types', []):
                transaction.add(ResponseType(client=client, type=typ))

            for scope in config.get('scopes', []):
                transaction.add(Scope(client=client, scope=scope))

            for contact in config.get('contacts', []):
                transaction.add(Contact(client=client, contact=contact))

            for jwk in config.get('jwks', []):
                transaction.add(JWKS(client=client, jwk=jwk))

            return transaction

    class RedirectURI(base_model):
        class Meta:
            table_name = 'redirect_uri'

        client = ForeignKeyField(
            Client, column_name='client', backref='redirect_uris',
            lazy_load=False, on_delete='CASCADE', on_update='CASCADE'
        )
        uri = TextField()

    class GrantType(base_model):
        class Meta:
            table_name = 'grant_type'

        client = ForeignKeyField(
            Client, column_name='client', backref='grant_types',
            lazy_load=False, on_delete='CASCADE', on_update='CASCADE'
        )
        type = TextField()

    class ResponseType(base_model):
        class Meta:
            table_name = 'response_type'

        client = ForeignKeyField(
            Client, column_name='client', backref='response_types',
            lazy_load=False, on_delete='CASCADE', on_update='CASCADE'
        )
        type = TextField()

    class Scope(base_model):
        class Meta:
            table_name = 'scope'

        client = ForeignKeyField(
            Client, column_name='client', backref='scopes', lazy_load=False,
            on_delete='CASCADE', on_update='CASCADE'
        )
        scope = TextField()

    class Contact(base_model):
        class Meta:
            table_name = 'contact'

        client = ForeignKeyField(
            Client, column_name='client', backref='contacts', lazy_load=False,
            on_delete='CASCADE', on_update='CASCADE'
        )
        contact = TextField()

    class JWKS(base_model):
        class Meta:
            table_name = 'jwks'

        client = ForeignKeyField(
            Client, column_name='client', backref='jwks', lazy_load=False,
            on_delete='CASCADE', on_update='CASCADE'
        )
        jwk = JSONTextField(serialize=json_dumps, deserialize=json_loads)

    class Token(base_model, OAuth2TokenMixin):
        """An OAuth bearer token."""

        user = ForeignKeyField(
            user_model, column_name='user', lazy_load=False,
            on_delete='CASCADE', on_update='CASCADE'
        )
        client_id = CharField(48, null=True)
        token_type = CharField(40, null=True)
        access_token = CharField(255, unique=True)
        refresh_token = CharField(255, index=True, null=True)
        scope = TextField(default='')
        revoked = BooleanField(default=False)
        issued_at = DateTimeField(default=datetime.now)
        expires_in = IntegerField(default=0)

    class AuthorizationCode(base_model, OAuth2AuthorizationCodeMixin):
        """An OAuth authorization code."""

        class Meta:
            table_name = 'authorization_code'

        user = ForeignKeyField(
            user_model, column_name='user', lazy_load=False,
            on_delete='CASCADE', on_update='CASCADE'
        )
        code = CharField(120, unique=True)
        client_id = CharField(48, null=True)
        redirect_uri = TextField(default='')
        response_type = TextField(default='')
        scope = TextField(default='')
        nonce = TextField(null=True)
        auth_time = DateTimeField(default=datetime.now)
        code_challenge = TextField(null=True)
        code_challenge_method = CharField(48, null=True)

        def create_authorization_code(
                self, client: Client, grant_user: user_model, request: Any
        ) -> str:
            """Create authorization code with
            additional nonce for OpenID Connect.
            """
            record = type(self)(
                code=(code := generate_token(48)),
                client_id=client.client_id,
                redirect_uri=request.redirect_uri,
                scope=request.scope,
                user_id=grant_user.id,
                # OpenID request *may* have "nonce" parameter
                nonce=request.data.get('nonce')
            )
            record.save()
            return code

    return OAuth2Models(
        user_model,
        Client,
        RedirectURI,
        GrantType,
        ResponseType,
        Scope,
        Contact,
        JWKS,
        Token,
        AuthorizationCode
    )
