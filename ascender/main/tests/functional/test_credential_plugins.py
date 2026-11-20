import pytest
from unittest import mock
from ascender.main.credential_plugins import hashivault


def test_azure_cloud_name_choices():
    from ascender.main.credential_plugins import azure_kv

    assert len(azure_kv.CLOUD_NAMES) > 0
    assert azure_kv.DEFAULT_CLOUD_NAME in azure_kv.CLOUD_NAMES
    cloud_field = next((f for f in azure_kv.azure_keyvault_inputs['fields'] if f['id'] == 'cloud_name'), None)
    assert cloud_field is not None, 'cloud_name field missing from azure_keyvault_inputs'
    assert cloud_field['choices'] == azure_kv.CLOUD_NAMES
    assert cloud_field['default'] == azure_kv.DEFAULT_CLOUD_NAME


@pytest.mark.parametrize(
    'cloud_name, expected_authority',
    [
        (None, 'login.microsoftonline.com'),
        ('AzureCloud', 'login.microsoftonline.com'),
        ('AzureUSGovernment', 'login.microsoftonline.us'),
        ('AzureChinaCloud', 'login.chinacloudapi.cn'),
        ('AzureGermanCloud', 'login.microsoftonline.de'),
    ],
)
def test_azure_backend_authority(cloud_name, expected_authority):
    from ascender.main.credential_plugins import azure_kv

    kwargs = {'tenant': 't', 'client': 'c', 'secret': 's', 'url': 'https://example.vault.azure.net', 'secret_field': 'foo'}
    if cloud_name is not None:
        kwargs['cloud_name'] = cloud_name
    # the SDK is imported inside the backend, so the patch has to land on the
    # module it is imported from rather than on azure_kv
    with mock.patch('azure.identity.ClientSecretCredential') as csc, mock.patch('azure.keyvault.secrets.SecretClient'):
        azure_kv.azure_keyvault_backend(**kwargs)
    assert csc.call_args.kwargs['authority'] == expected_authority


def test_azure_authority_hosts_match_the_sdk():
    """azure_kv spells the authority hosts out so it need not import the SDK.

    They are constants rather than a moving target, but if Microsoft ever
    changes one this is where it should fail.
    """
    from azure.identity import AzureAuthorityHosts

    from ascender.main.credential_plugins import azure_kv

    assert azure_kv.AUTHORITY_HOSTS['AzureChinaCloud'] == AzureAuthorityHosts.AZURE_CHINA
    assert azure_kv.AUTHORITY_HOSTS['AzureCloud'] == AzureAuthorityHosts.AZURE_PUBLIC_CLOUD
    assert azure_kv.AUTHORITY_HOSTS['AzureUSGovernment'] == AzureAuthorityHosts.AZURE_GOVERNMENT


AZURE_KV_URL = 'https://example.vault.azure.net'


def test_azure_backend_client_secret_unchanged():
    """A credential with Client ID, Client Secret and Tenant ID, as every
    credential had to have before Managed Identity support, authenticates with
    the client secret exactly as before."""
    from ascender.main.credential_plugins import azure_kv

    kwargs = {'tenant': 't', 'client': 'c', 'secret': 's', 'url': AZURE_KV_URL, 'secret_field': 'foo', 'secret_version': 'v1'}
    with (
        mock.patch('azure.identity.ClientSecretCredential') as csc,
        mock.patch('azure.identity.ManagedIdentityCredential') as mic,
        mock.patch('azure.keyvault.secrets.SecretClient') as sc,
    ):
        sc.return_value.get_secret.return_value.value = 'the-secret'
        assert azure_kv.azure_keyvault_backend(**kwargs) == 'the-secret'
    csc.assert_called_once_with(tenant_id='t', client_id='c', client_secret='s', authority='login.microsoftonline.com')
    sc.assert_called_once_with(credential=csc.return_value, vault_url=AZURE_KV_URL)
    sc.return_value.get_secret.assert_called_once_with(name='foo', version='v1')
    mic.assert_not_called()


@pytest.mark.parametrize(
    'missing, message',
    [
        (('tenant',), 'Tenant ID must be set'),
        (('client',), 'Client ID must be set'),
        (('client', 'tenant'), 'Client ID and Tenant ID must be set'),
    ],
)
def test_azure_backend_client_secret_requires_client_and_tenant(missing, message):
    from ascender.main.credential_plugins import azure_kv

    kwargs = {'tenant': 't', 'client': 'c', 'secret': 's', 'url': AZURE_KV_URL, 'secret_field': 'foo'}
    for field in missing:
        kwargs[field] = ''
    with mock.patch('azure.identity.ManagedIdentityCredential') as mic, pytest.raises(ValueError, match=message):
        azure_kv.azure_keyvault_backend(**kwargs)
    mic.assert_not_called()


def test_azure_inputs_require_only_url_and_secret_field():
    from ascender.main.credential_plugins import azure_kv

    assert azure_kv.azure_keyvault_inputs['required'] == ['url', 'secret_field']


@pytest.fixture
def azure_workload_identity_env(tmp_path, monkeypatch):
    """The environment the Azure Workload Identity webhook gives a pod."""
    token_file = tmp_path / 'azure-identity-token'
    token_file.write_text('fake-jwt')
    for var in ('IDENTITY_ENDPOINT', 'IDENTITY_HEADER', 'IMDS_ENDPOINT', 'MSI_ENDPOINT', 'MSI_SECRET'):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv('AZURE_AUTHORITY_HOST', 'https://login.microsoftonline.com/')
    monkeypatch.setenv('AZURE_TENANT_ID', 'env-tenant')
    monkeypatch.setenv('AZURE_CLIENT_ID', 'env-client')
    monkeypatch.setenv('AZURE_FEDERATED_TOKEN_FILE', str(token_file))
    return token_file


@pytest.mark.parametrize(
    'client, expected_client_id',
    [
        ('', 'env-client'),  # no Client ID: the identity in AZURE_CLIENT_ID
        ('kv-reader', 'kv-reader'),  # an explicit Client ID overrides AZURE_CLIENT_ID
    ],
)
def test_azure_backend_workload_identity(azure_workload_identity_env, client, expected_client_id):
    from ascender.main.credential_plugins import azure_kv

    kwargs = {'client': client, 'secret': '', 'tenant': '', 'url': AZURE_KV_URL, 'secret_field': 'foo'}
    # ManagedIdentityCredential is real: it has to pick Workload Identity from
    # the environment, which is the behaviour under test
    with mock.patch('azure.identity._credentials.workload_identity.WorkloadIdentityCredential') as wic, mock.patch('azure.keyvault.secrets.SecretClient') as sc:
        sc.return_value.get_secret.return_value.value = 'the-secret'
        assert azure_kv.azure_keyvault_backend(**kwargs) == 'the-secret'
    wic.assert_called_once_with(tenant_id='env-tenant', client_id=expected_client_id, token_file_path=str(azure_workload_identity_env))
    sc.return_value.get_secret.assert_called_once_with(name='foo', version='')


def test_azure_backend_workload_identity_without_any_client_id(azure_workload_identity_env, monkeypatch):
    from ascender.main.credential_plugins import azure_kv

    monkeypatch.delenv('AZURE_CLIENT_ID')
    with pytest.raises(RuntimeError, match='Workload Identity needs a Client ID'):
        azure_kv.azure_keyvault_backend(url=AZURE_KV_URL, secret_field='foo')


def _azure_backend_failing_with(error, **kwargs):
    from ascender.main.credential_plugins import azure_kv

    with mock.patch('azure.identity.ManagedIdentityCredential'), mock.patch('azure.keyvault.secrets.SecretClient') as sc:
        sc.return_value.get_secret.side_effect = error
        azure_kv.azure_keyvault_backend(url=AZURE_KV_URL, secret_field='foo', **kwargs)


def test_azure_backend_managed_identity_unavailable():
    from azure.identity import CredentialUnavailableError

    with pytest.raises(RuntimeError, match='No Workload Identity or Managed Identity is available'):
        _azure_backend_failing_with(CredentialUnavailableError('no identity'))


def test_azure_backend_managed_identity_authentication_failure():
    from azure.core.exceptions import ClientAuthenticationError

    with pytest.raises(RuntimeError, match='Could not authenticate to Azure Key Vault as identity kv-reader: AADSTS700016'):
        _azure_backend_failing_with(ClientAuthenticationError('AADSTS700016'), client='kv-reader')


@pytest.mark.parametrize(
    'client, identity',
    [
        ('kv-reader', 'identity kv-reader'),
        ('', 'the default identity of the environment'),
    ],
)
def test_azure_backend_managed_identity_access_denied(client, identity):
    from azure.core.exceptions import HttpResponseError

    error = HttpResponseError('Forbidden')
    error.status_code = 403
    with pytest.raises(RuntimeError, match=f'Azure Key Vault denied access to {identity}'):
        _azure_backend_failing_with(error, client=client)


def test_azure_backend_managed_identity_other_errors_pass_through():
    from azure.core.exceptions import ResourceNotFoundError

    with pytest.raises(ResourceNotFoundError):
        _azure_backend_failing_with(ResourceNotFoundError('SecretNotFound'), client='kv-reader')


def test_hashivault_approle_auth():
    kwargs = {
        'role_id': 'the_role_id',
        'secret_id': 'the_secret_id',
    }
    expected_res = {
        'role_id': 'the_role_id',
        'secret_id': 'the_secret_id',
    }
    res = hashivault.approle_auth(**kwargs)
    assert res == expected_res


def test_hashivault_kubernetes_auth():
    kwargs = {
        'kubernetes_role': 'the_kubernetes_role',
    }
    expected_res = {
        'role': 'the_kubernetes_role',
        'jwt': 'the_jwt',
    }
    with mock.patch('pathlib.Path') as path_mock:
        mock.mock_open(path_mock.return_value.open, read_data='the_jwt')
        res = hashivault.kubernetes_auth(**kwargs)
        path_mock.assert_called_with('/var/run/secrets/kubernetes.io/serviceaccount/token')
        assert res == expected_res


def test_hashivault_client_cert_auth_explicit_role():
    kwargs = {
        'client_cert_role': 'test-cert-1',
    }
    expected_res = {
        'name': 'test-cert-1',
    }
    res = hashivault.client_cert_auth(**kwargs)
    assert res == expected_res


def test_hashivault_client_cert_auth_no_role():
    kwargs = {}
    expected_res = {
        'name': None,
    }
    res = hashivault.client_cert_auth(**kwargs)
    assert res == expected_res


def test_hashivault_userpass_auth():
    kwargs = {'username': 'the_username', 'password': 'the_password'}
    expected_res = {'username': 'the_username', 'password': 'the_password'}
    res = hashivault.userpass_auth(**kwargs)
    assert res == expected_res


def test_hashivault_handle_auth_token():
    kwargs = {
        'token': 'the_token',
    }
    token = hashivault.handle_auth(**kwargs)
    assert token == kwargs['token']


def test_hashivault_handle_auth_approle():
    kwargs = {
        'role_id': 'the_role_id',
        'secret_id': 'the_secret_id',
    }
    with mock.patch.object(hashivault, 'method_auth') as method_mock:
        method_mock.return_value = 'the_token'
        token = hashivault.handle_auth(**kwargs)
        method_mock.assert_called_with(**kwargs, auth_param=kwargs)
        assert token == 'the_token'


def test_hashivault_handle_auth_kubernetes():
    kwargs = {
        'kubernetes_role': 'the_kubernetes_role',
    }
    with mock.patch.object(hashivault, 'method_auth') as method_mock:
        with mock.patch('pathlib.Path') as path_mock:
            mock.mock_open(path_mock.return_value.open, read_data='the_jwt')
            method_mock.return_value = 'the_token'
            token = hashivault.handle_auth(**kwargs)
            method_mock.assert_called_with(**kwargs, auth_param={'role': 'the_kubernetes_role', 'jwt': 'the_jwt'})
            assert token == 'the_token'


def test_hashivault_handle_auth_client_cert():
    kwargs = {
        'client_cert_public': "foo",
        'client_cert_private': "bar",
        'client_cert_role': 'test-cert-1',
    }
    auth_params = {
        'name': 'test-cert-1',
    }
    with mock.patch.object(hashivault, 'method_auth') as method_mock:
        method_mock.return_value = 'the_token'
        token = hashivault.handle_auth(**kwargs)
        method_mock.assert_called_with(**kwargs, auth_param=auth_params)
        assert token == 'the_token'


def test_hashivault_handle_auth_not_enough_args():
    with pytest.raises(Exception):
        hashivault.handle_auth()


class TestDelineaImports:
    """
    These module have a try-except for ImportError which will allow using the older library
    but we do not want the awx_devel image to have the older library,
    so these tests are designed to fail if these wind up using the fallback import
    """

    def test_dsv_import(self):
        from ascender.main.credential_plugins.dsv import SecretsVault  # noqa

        # assert this module as opposed to older thycotic.secrets.vault
        assert SecretsVault.__module__ == 'delinea.secrets.vault'

    def test_tss_import(self):
        from ascender.main.credential_plugins.tss import DomainPasswordGrantAuthorizer, PasswordGrantAuthorizer, SecretServer, ServerSecret  # noqa

        for cls in (DomainPasswordGrantAuthorizer, PasswordGrantAuthorizer, SecretServer, ServerSecret):
            # assert this module as opposed to older thycotic.secrets.server
            assert cls.__module__ == 'delinea.secrets.server'
