# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from azure.cli.core.commands import LongRunningOperation
from azure.cli.core.util import CLIError
from ._utils import (get_resource_group_name_by_registry_name, add_months_to_now,
                     get_registry_by_name)
from .scope_map import _parse_actions_from_repositories
from ._client_factory import cf_acr_scope_maps, cf_acr_token_credentials, cf_acr_registries

SCOPE_MAPS = 'scopeMaps'
TOKENS = 'tokens'


def acr_token_create(cmd,
                     client,
                     registry_name,
                     token_name,
                     scope_map_name=None,
                     repositories=None,
                     status=None,
                     resource_group_name=None,
                     generate_password1=None,
                     generate_password2=None,
                     expiry=None):

    if bool(repositories) == bool(scope_map_name):
        raise CLIError('usage error: --add-repository | --scope-map-name')
    if generate_password1 is None:
        generate_password1 = True
    if generate_password2 is None:
        generate_password2 = True
    resource_group_name = get_resource_group_name_by_registry_name(cmd.cli_ctx, registry_name, resource_group_name)
    if repositories:
        scope_map_name = token_name + '-scope-map'
        scope_map_client = cf_acr_scope_maps(cmd.cli_ctx)
        poller = scope_map_client.create(resource_group_name, registry_name, scope_map_name,
                                         _parse_actions_from_repositories(repositories),
                                         "Token {}'s scope map".format(token_name))
        scope_map = LongRunningOperation(cmd.cli_ctx)(poller)
        scope_map_id = scope_map.id
    else:
        arm_resource_id = get_registry_by_name(cmd.cli_ctx, registry_name, resource_group_name)[0].id
        scope_map_id = '{}/{}/{}'.format(arm_resource_id, SCOPE_MAPS, scope_map_name)

    TokenModelType = cmd.get_models('Token')
    poller = client.create(
        resource_group_name,
        registry_name,
        token_name,
        TokenModelType(
            scope_map_id=scope_map_id,
            status=status
        )
    )
    token = LongRunningOperation(cmd.cli_ctx)(poller)

    if generate_password1 or generate_password2:
        cred_client = cf_acr_token_credentials(cmd.cli_ctx)
        poller = acr_token_credential_generate(cmd, cred_client, registry_name, token_name, bool(generate_password1),
                                               bool(generate_password2), expiry,
                                               resource_group_name=resource_group_name)
        credentials = LongRunningOperation(cmd.cli_ctx)(poller)
        #setattr(token, 'username', credentials.username)
        #setattr(token, 'passwords', credentials.passwords)
        setattr(token.credentials, 'username', credentials.username)
        setattr(token.credentials, "passwords", credentials.passwords)
        registry_client = cf_acr_registries(cmd.cli_ctx)
        login_server = registry_client.get(resource_group_name, registry_name).login_server
        from knack.log import get_logger
        logger = get_logger(__name__)

        logger.warning('Please save generated password to a safe place. Meanwhile you can consume it through'
                       ' "docker login %s -u %s -p %s"', login_server, token.credentials.username,
                       token.credentials.passwords[0].value)

    return token


def acr_token_delete(cmd,
                     client,
                     registry_name,
                     token_name,
                     yes=None,
                     resource_group_name=None):

    if not yes:
        from knack.prompting import prompt_y_n
        confirmation = prompt_y_n("Deleting the token '{}' will invalidate access to anyone using its credentials. "
                                  "Proceed?".format(token_name))

        if not confirmation:
            return None

    resource_group_name = get_resource_group_name_by_registry_name(cmd.cli_ctx, registry_name, resource_group_name)
    return client.delete(resource_group_name, registry_name, token_name)


def acr_token_update(cmd,
                     client,
                     registry_name,
                     token_name,
                     scope_map_name=None,
                     status=None,
                     resource_group_name=None,
                     repositories=None,
                     generate_password1=None,
                     generate_password2=None,
                     delete_password1=None,
                     delete_password2=None,
                     expiry=None):
    if repositories and scope_map_name:
        raise CLIError("usage error: --respositories | --scope-map-name")
    resource_group_name = get_resource_group_name_by_registry_name(cmd.cli_ctx, registry_name, resource_group_name)
    if repositories:
        scope_map_name = token_name + '-scope-map'  # TODO: normalize the name

        scope_map_client = cf_acr_scope_maps(cmd.cli_ctx)
        poller = scope_map_client.create(resource_group_name, registry_name, scope_map_name,
                                         _parse_actions_from_repositories(repositories),
                                         "Token {}'s scope map".format(token_name))
        scope_map = LongRunningOperation(cmd.cli_ctx)(poller)
        scope_map_id = scope_map.id
    elif scope_map_name:
        arm_resource_id = get_registry_by_name(cmd.cli_ctx, registry_name, resource_group_name)[0].id
        scope_map_id = '{}/{}/{}'.format(arm_resource_id, SCOPE_MAPS, scope_map_name)
    elif scope_map_name == '':
        scope_map_id = None
    else:
        scope_map_id = client.get(resource_group_name, registry_name, token_name).scope_map_id

    TokenUpdateParameters = cmd.get_models('TokenUpdateParameters')
    poller = client.update(
        resource_group_name,
        registry_name,
        token_name,
        TokenUpdateParameters(
            scope_map_id=scope_map_id,
            status=status
        )
    )
    token = LongRunningOperation(cmd.cli_ctx)(poller)
    cred_client = cf_acr_token_credentials(cmd.cli_ctx)
    if delete_password1 or delete_password2:
        poller = acr_token_credential_delete(cmd, client, registry_name, token_name, bool(delete_password1),
                                             bool(delete_password2), resource_group_name)
        token = LongRunningOperation(cmd.cli_ctx)(poller)
    if generate_password1 or generate_password2:
        poller = acr_token_credential_generate(cmd, cred_client, registry_name, token_name, bool(generate_password1),
                                               bool(generate_password2), expiry,
                                               resource_group_name=resource_group_name)
        credentials = LongRunningOperation(cmd.cli_ctx)(poller)
        setattr(token.credentials, 'username', credentials.username)
        setattr(token.credentials, "passwords", credentials.passwords)

    return token


def acr_token_show(cmd,
                   client,
                   registry_name,
                   token_name,
                   resource_group_name=None):

    resource_group_name = get_resource_group_name_by_registry_name(cmd.cli_ctx, registry_name, resource_group_name)

    return client.get(
        resource_group_name,
        registry_name,
        token_name
    )


def acr_token_list(cmd,
                   client,
                   registry_name,
                   resource_group_name=None):

    resource_group_name = get_resource_group_name_by_registry_name(cmd.cli_ctx, registry_name, resource_group_name)

    return client.list(
        resource_group_name,
        registry_name
    )


# Credential functions
def acr_token_credential_generate(cmd,
                                  client,
                                  registry_name,
                                  token_name,
                                  password1=False,
                                  password2=False,
                                  expiry=None,
                                  months=None,
                                  resource_group_name=None):
    resource_group_name = get_resource_group_name_by_registry_name(cmd.cli_ctx, registry_name, resource_group_name)
    arm_resource_id = get_registry_by_name(cmd.cli_ctx, registry_name, resource_group_name)[0].id
    token_id = '{}/{}/{}'.format(arm_resource_id, TOKENS, token_name)

    # We only want to specify a password if only one was passed.
    name = ("password1" if password1 else "password2") if password1 ^ password2 else None

    if months and not expiry:
        expiry = add_months_to_now(months).isoformat(sep='T')

    GenerateCredentialsParameters = cmd.get_models('GenerateCredentialsParameters')

    return client.generate_credentials(
        resource_group_name,
        registry_name,
        GenerateCredentialsParameters(
            token_id=token_id,
            name=name,
            expiry=expiry
        )
    )


def acr_token_credential_delete(cmd,
                                client,
                                registry_name,
                                token_name,
                                password1=False,
                                password2=False,
                                resource_group_name=None):

    resource_group_name = get_resource_group_name_by_registry_name(cmd.cli_ctx, registry_name, resource_group_name)

    if not (password1 or password2):
        raise CLIError("Nothing to delete")

    TokenPassword = cmd.get_models('TokenPassword')

    if password1 and password2:
        new_password_payload = []
    elif password1:
        new_password_payload = [
            TokenPassword(
                name="password2"
            )
        ]
    else:
        new_password_payload = [
            TokenPassword(
                name="password1"
            )
        ]

    TokenUpdateParameters = cmd.get_models('TokenUpdateParameters')
    TokenCredentialsProperties = cmd.get_models('TokenCredentialsProperties')

    return client.update(
        resource_group_name,
        registry_name,
        token_name,
        TokenUpdateParameters(
            credentials=TokenCredentialsProperties(
                passwords=new_password_payload
            )
        )
    )
