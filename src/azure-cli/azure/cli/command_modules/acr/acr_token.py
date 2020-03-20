# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from msrestazure.azure_exceptions import CloudError
from azure.cli.core.commands import LongRunningOperation
from azure.cli.core.util import CLIError
from ._utils import get_resource_group_name_by_registry_name, parse_actions_from_repositories

SCOPE_MAPS = 'scopeMaps'
TOKENS = 'tokens'
DEF_SCOPE_MAP_NAME_TEMPLATE = '{}-scope-map'  # append - to minimize incidental collision

# pylint: disable=too-many-locals


def acr_token_create(cmd,
                     client,
                     registry_name,
                     token_name,
                     scope_map_name=None,
                     repository_actions_list=None,
                     status=None,
                     resource_group_name=None,
                     no_passwords=None,
                     active_directory_object=None):
    from knack.log import get_logger
    from ._utils import get_resource_id_by_registry_name

    if bool(repository_actions_list) == bool(scope_map_name):
        raise CLIError("usage error: --repository | --scope-map-name")
    if no_passwords and active_directory_object:
        raise CLIError("usage error: --no-passwords only apples on token with password credentials")

    no_passwords = no_passwords or active_directory_object

    resource_group_name = get_resource_group_name_by_registry_name(cmd.cli_ctx, registry_name, resource_group_name)

    logger = get_logger(__name__)
    if repository_actions_list:
        scope_map_id = _create_default_scope_map(cmd, resource_group_name, registry_name,
                                                 token_name, repository_actions_list, logger)
    else:
        arm_resource_id = get_resource_id_by_registry_name(cmd.cli_ctx, registry_name)
        scope_map_id = '{}/{}/{}'.format(arm_resource_id, SCOPE_MAPS, scope_map_name)

    Token = cmd.get_models('Token')

    credentials = None
    if active_directory_object:
        from azure.cli.core._profile import Profile
        object_id = _resolve_object_id(cmd.cli_ctx, active_directory_object, fallback_to_object_id=True)
        TokenCredentialsProperties, ActiveDirectoryObject = cmd.get_models('TokenCredentialsProperties',
                                                                           'ActiveDirectoryObject')
        profile = Profile(cli_ctx=cmd.cli_ctx)
        _, _, tenant_id = profile.get_login_credentials()

        credentials = TokenCredentialsProperties(
            active_directory_object=ActiveDirectoryObject(object_id=object_id,
                                                          tenant_id=tenant_id))
    poller = client.create(
        resource_group_name,
        registry_name,
        token_name,
        Token(
            scope_map_id=scope_map_id,
            credentials=credentials,
            status=status
        )
    )

    if no_passwords:
        return poller

    token = LongRunningOperation(cmd.cli_ctx)(poller)
    _create_default_passwords(cmd, resource_group_name, registry_name, token, logger)
    return token


def _create_default_scope_map(cmd, resource_group_name, registry_name, token_name, repositories, logger):
    from ._client_factory import cf_acr_scope_maps
    scope_map_name = DEF_SCOPE_MAP_NAME_TEMPLATE.format(token_name)
    scope_map_client = cf_acr_scope_maps(cmd.cli_ctx)
    actions = parse_actions_from_repositories(repositories)
    try:
        existing_scope_map = scope_map_client.get(resource_group_name, registry_name, scope_map_name)
        # for command idempotency, if the actions are the same, we accept it
        if sorted(existing_scope_map.actions) == sorted(actions):
            return existing_scope_map.id
        raise CLIError('The default scope map was already configured with different repository permissions.'
                       '\nPlease use "az acr scope-map update -r {} -n {} --add <REPO> --remove <REPO>" to update.'
                       .format(registry_name, scope_map_name))
    except CloudError:
        pass
    logger.warning('Creating a scope map "%s" for provided repository permissions.', scope_map_name)
    poller = scope_map_client.create(resource_group_name, registry_name, scope_map_name,
                                     actions, "Created by token: {}".format(token_name))
    scope_map = LongRunningOperation(cmd.cli_ctx)(poller)
    return scope_map.id


def _create_default_passwords(cmd, resource_group_name, registry_name, token, logger):
    from ._client_factory import cf_acr_token_credentials, cf_acr_registries
    cred_client = cf_acr_token_credentials(cmd.cli_ctx)
    poller = acr_token_credential_generate(cmd, cred_client, registry_name, token.name,
                                           password1=True, password2=True, days=None,
                                           resource_group_name=resource_group_name)
    credentials = LongRunningOperation(cmd.cli_ctx)(poller)
    setattr(token.credentials, 'username', credentials.username)
    setattr(token.credentials, 'passwords', credentials.passwords)
    registry_client = cf_acr_registries(cmd.cli_ctx)
    login_server = registry_client.get(resource_group_name, registry_name).login_server
    logger.warning('Please store your generated credentials safely. Meanwhile you can use it through'
                   ' "docker login %s -u %s -p %s".', login_server, token.credentials.username,
                   token.credentials.passwords[0].value)


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
                     resource_group_name=None):

    resource_group_name = get_resource_group_name_by_registry_name(cmd.cli_ctx, registry_name, resource_group_name)

    from ._utils import get_resource_id_by_registry_name

    TokenUpdateParameters = cmd.get_models('TokenUpdateParameters')

    scope_map_id = None
    if scope_map_name:
        arm_resource_id = get_resource_id_by_registry_name(cmd.cli_ctx, registry_name)
        scope_map_id = '{}/{}/{}'.format(arm_resource_id, SCOPE_MAPS, scope_map_name)

    return client.update(
        resource_group_name,
        registry_name,
        token_name,
        TokenUpdateParameters(
            scope_map_id=scope_map_id,
            status=status
        )
    )


def acr_token_show(cmd,
                   client,
                   registry_name,
                   token_name,
                   resource_group_name=None,
                   show_details=None):

    resource_group_name = get_resource_group_name_by_registry_name(cmd.cli_ctx, registry_name, resource_group_name)

    acr_token = client.get(
        resource_group_name,
        registry_name,
        token_name
    )

    if show_details:
        _back_fill_object_name(cmd.cli_ctx, [acr_token])

    return acr_token


def acr_token_list(cmd,
                   client,
                   registry_name,
                   resource_group_name=None,
                   show_details=None):

    resource_group_name = get_resource_group_name_by_registry_name(cmd.cli_ctx, registry_name, resource_group_name)

    acr_tokens = client.list(
        resource_group_name,
        registry_name
    )

    acr_tokens = list(acr_tokens)
    if show_details:
        _back_fill_object_name(cmd.cli_ctx, acr_tokens)
    return acr_tokens


# Credential functions
def acr_token_credential_generate(cmd,
                                  client,
                                  registry_name,
                                  token_name,
                                  password1=False,
                                  password2=False,
                                  days=None,
                                  resource_group_name=None):

    from ._utils import get_resource_id_by_registry_name

    resource_group_name = get_resource_group_name_by_registry_name(cmd.cli_ctx, registry_name, resource_group_name)
    arm_resource_id = get_resource_id_by_registry_name(cmd.cli_ctx, registry_name)
    token_id = '{}/{}/{}'.format(arm_resource_id, TOKENS, token_name)

    # We only want to specify a password if only one was passed.
    name = ("password1" if password1 else "password2") if password1 ^ password2 else None
    expiry = None
    if days:
        from ._utils import add_days_to_now
        expiry = add_days_to_now(days)

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

    if not (password1 or password2):
        raise CLIError('No credentials to delete.')

    resource_group_name = get_resource_group_name_by_registry_name(cmd.cli_ctx, registry_name, resource_group_name)

    token = client.get(
        resource_group_name,
        registry_name,
        token_name
    )

    # retrieve the set of existing Token password names. Eg: {'password1', 'password2'}
    password_names = set(map(lambda password: password.name, token.credentials.passwords))

    if password1 and 'password1' not in password_names:
        raise CLIError('Unable to perform operation. Password1 credential doesn\'t exist.')
    if password2 and 'password2' not in password_names:
        raise CLIError('Unable to perform operation. Password2 credential doesn\'t exist.')

    # remove the items which are supposed to be deleted
    if password1:
        password_names.remove('password1')
    if password2:
        password_names.remove('password2')

    TokenPassword = cmd.get_models('TokenPassword')
    new_password_payload = list(map(lambda name: TokenPassword(name=name), password_names))

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


def _graph_client_factory(cli_ctx, **_):
    from azure.cli.core._profile import Profile
    from azure.cli.core.commands.client_factory import configure_common_settings
    from azure.graphrbac import GraphRbacManagementClient
    profile = Profile(cli_ctx=cli_ctx)
    cred, _, tenant_id = profile.get_login_credentials(
        resource=cli_ctx.cloud.endpoints.active_directory_graph_resource_id)
    client = GraphRbacManagementClient(cred, tenant_id,
                                       base_url=cli_ctx.cloud.endpoints.active_directory_graph_resource_id)
    configure_common_settings(cli_ctx, client)
    return client


def _get_object_stubs(graph_client, assignees):
    from azure.graphrbac.models import GetObjectsParameters
    result = []
    assignees = list(assignees)  # callers could pass in a set
    for i in range(0, len(assignees), 1000):
        params = GetObjectsParameters(include_directory_object_references=True, object_ids=assignees[i:i + 1000])
        result += list(graph_client.objects.get_objects_by_object_ids(params))
    return result


def _get_displayable_name(graph_object):
    if getattr(graph_object, 'user_principal_name', None):
        return graph_object.user_principal_name
    if getattr(graph_object, 'service_principal_names', None):
        return graph_object.service_principal_names[0]
    return graph_object.display_name or ''


def _back_fill_object_name(cli_ctx, acr_tokens):
    name_mappings = {t.credentials.active_directory_object.object_id: None
                     for t in acr_tokens if t.credentials and t.credentials.active_directory_object}

    if name_mappings:
        client = _graph_client_factory(cli_ctx)
        keys = name_mappings.keys()
        stubs = _get_object_stubs(client, keys)
        for k, s in zip(keys, stubs):
            name_mappings[k] = _get_displayable_name(s)
        for t in acr_tokens:
            setattr(t.credentials.active_directory_object, 'object_name',
                    name_mappings[t.credentials.active_directory_object.object_id])


def _resolve_object_id(cli_ctx, assignee, fallback_to_object_id=False):
    from azure.graphrbac.models import GraphErrorException
    client = _graph_client_factory(cli_ctx)
    result = None
    try:
        if assignee.find('@') >= 0:  # looks like a user principal name
            result = list(client.users.list(filter="userPrincipalName eq '{}'".format(assignee)))
        if not result:
            result = list(client.service_principals.list(
                filter="servicePrincipalNames/any(c:c eq '{}')".format(assignee)))
        if not result and _is_guid(assignee):  # assume an object id, let us verify it
            result = _get_object_stubs(client, [assignee])

        # 2+ matches should never happen, so we only check 'no match' here
        if not result:
            raise CLIError("No matches in graph database for '{}'".format(assignee))

        return result[0].object_id
    except (CloudError, GraphErrorException):
        if fallback_to_object_id and _is_guid(assignee):
            return assignee
        raise


def _is_guid(guid):
    import uuid
    try:
        uuid.UUID(guid)
        return True
    except ValueError:
        return False
