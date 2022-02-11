"""OAuth2 authentication framework generator."""

from typing import Any, Iterable, NamedTuple, Optional, Type

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.integrations.flask_oauth2 import ResourceProtector
from peewee import Model

from oauth2gen.orm import OAuth2Models, create_models
from oauth2gen.oauth2 import BearerTokenValidator, create_authorization_server


__all__ = ['OAuth2Framework', 'create_framework']


class OAuth2Framework(NamedTuple):
    """Represents an authorization framework."""

    models: OAuth2Models
    authorization_server: Type[AuthorizationServer]
    resource_protector: ResourceProtector


def create_framework(
        user_model: Type[Model],
        config: dict[str, Any],
        *,
        base_model: Optional[Type[Model]] = None,
        auth_methods: Iterable[str] = ('client_secret_post',),
        implicit_grant: bool = True,
        include_new_refresh_token: bool = True
) -> OAuth2Framework:
    """Creates an OAuth2 framework."""

    models = create_models(user_model, config, base_model=base_model)
    authorization_server = create_authorization_server(
        models,
        config.get('url'),
        auth_methods=auth_methods,
        implicit_grant=implicit_grant,
        include_new_refresh_token=include_new_refresh_token
    )
    resource_protector = ResourceProtector()
    resource_protector.register_token_validator(
        BearerTokenValidator(models.token)
    )
    return OAuth2Framework(models, authorization_server, resource_protector)
