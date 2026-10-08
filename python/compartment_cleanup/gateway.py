"""Explicit OCI SDK boundary: code selects operations, live responses select KMS endpoints.

SDK failures remain unresolved; only service handlers can establish deletion evidence.
No credential, request payload, or raw SDK exception is included in diagnostics.
"""
from datetime import date, datetime
from urllib.parse import urlsplit

import oci

from .model import CleanupError


# Static method bindings, never a method name supplied by a saved plan.
_OPERATIONS = {
    ("compute_management", "list_instance_pools"): ("read", lambda c, p: c.list_instance_pools(**p)),
    ("compute_management", "list_instance_pool_instances"): ("read", lambda c, p: c.list_instance_pool_instances(**p)),
    ("container_engine", "list_clusters"): ("read", lambda c, p: c.list_clusters(**p)),
    ("container_engine", "list_node_pools"): ("read", lambda c, p: c.list_node_pools(**p)),
    ("container_engine", "get_node_pool"): ("read", lambda c, p: c.get_node_pool(**p)),
    ("network", "list_vlans"): ("read", lambda c, p: c.list_vlans(**p)),
    ("network", "get_vlan"): ("read", lambda c, p: c.get_vlan(**p)),
    ("network", "list_drg_attachments"): ("read", lambda c, p: c.list_drg_attachments(**p)),
    ("network", "get_drg_attachment"): ("read", lambda c, p: c.get_drg_attachment(**p)),
    ("network", "list_network_security_group_security_rules"): ("read", lambda c, p: c.list_network_security_group_security_rules(**p)),
    ("dns", "list_resolvers"): ("read", lambda c, p: c.list_resolvers(**p)),
    ("dns", "get_resolver"): ("read", lambda c, p: c.get_resolver(**p)),
    ("dns", "list_resolver_endpoints"): ("read", lambda c, p: c.list_resolver_endpoints(**p)),
    ("dns", "get_resolver_endpoint"): ("read", lambda c, p: c.get_resolver_endpoint(**p)),
    ("dns", "get_view"): ("read", lambda c, p: c.get_view(**p)),
    ("dns", "list_zones"): ("read", lambda c, p: c.list_zones(**p)),
    ("dns", "get_zone"): ("read", lambda c, p: c.get_zone(**p)),
    ("network", "list_ipv6s"): ("read", lambda c, p: c.list_ipv6s(**p)),
    ("network", "get_private_ip"): ("read", lambda c, p: c.get_private_ip(**p)),
    ("network", "get_public_ip"): ("read", lambda c, p: c.get_public_ip(**p)),
    ("network", "list_public_ips"): ("read", lambda c, p: c.list_public_ips(**p)),
    ("identity", "list_bulk_action_resource_types"): ("read", lambda c, p: c.list_bulk_action_resource_types(**p)),
    ("identity", "bulk_delete_resources"): ("write", lambda c, p: c.bulk_delete_resources(**p)),
    ("identity", "get_work_request"): ("read", lambda c, p: c.get_work_request(**p)),
    ("identity", "get_compartment"): ("read", lambda c, p: c.get_compartment(**p)),
    ("identity", "list_compartments"): ("read", lambda c, p: c.list_compartments(**p)),
    ("identity", "list_region_subscriptions"): ("read", lambda c, p: c.list_region_subscriptions(**p)),
    ("identity", "list_policies"): ("read", lambda c, p: c.list_policies(**p)),
    ("identity", "get_policy"): ("read", lambda c, p: c.get_policy(**p)),
    ("identity", "delete_policy"): ("write", lambda c, p: c.delete_policy(**p)),
    ("identity", "list_availability_domains"): ("read", lambda c, p: c.list_availability_domains(**p)),
    ("compute", "list_instances"): ("read", lambda c, p: c.list_instances(**p)),
    ("compute", "get_instance"): ("read", lambda c, p: c.get_instance(**p)),
    ("compute", "terminate_instance"): ("write", lambda c, p: c.terminate_instance(**p)),
    ("compute", "list_vnic_attachments"): ("read", lambda c, p: c.list_vnic_attachments(**p)),
    ("compute", "get_vnic_attachment"): ("read", lambda c, p: c.get_vnic_attachment(**p)),
    ("compute", "list_volume_attachments"): ("read", lambda c, p: c.list_volume_attachments(**p)),
    ("compute", "get_volume_attachment"): ("read", lambda c, p: c.get_volume_attachment(**p)),
    ("compute", "detach_volume"): ("write", lambda c, p: c.detach_volume(**p)),
    ("compute", "list_boot_volume_attachments"): ("read", lambda c, p: c.list_boot_volume_attachments(**p)),
    ("compute", "get_boot_volume_attachment"): ("read", lambda c, p: c.get_boot_volume_attachment(**p)),
    ("compute", "detach_boot_volume"): ("write", lambda c, p: c.detach_boot_volume(**p)),
    ("network", "list_vcns"): ("read", lambda c, p: c.list_vcns(**p)),
    ("network", "get_vcn"): ("read", lambda c, p: c.get_vcn(**p)),
    ("network", "delete_vcn"): ("write", lambda c, p: c.delete_vcn(**p)),
    ("network", "list_subnets"): ("read", lambda c, p: c.list_subnets(**p)),
    ("network", "get_subnet"): ("read", lambda c, p: c.get_subnet(**p)),
    ("network", "delete_subnet"): ("write", lambda c, p: c.delete_subnet(**p)),
    ("network", "list_internet_gateways"): ("read", lambda c, p: c.list_internet_gateways(**p)),
    ("network", "get_internet_gateway"): ("read", lambda c, p: c.get_internet_gateway(**p)),
    ("network", "delete_internet_gateway"): ("write", lambda c, p: c.delete_internet_gateway(**p)),
    ("network", "list_nat_gateways"): ("read", lambda c, p: c.list_nat_gateways(**p)),
    ("network", "get_nat_gateway"): ("read", lambda c, p: c.get_nat_gateway(**p)),
    ("network", "delete_nat_gateway"): ("write", lambda c, p: c.delete_nat_gateway(**p)),
    ("network", "list_service_gateways"): ("read", lambda c, p: c.list_service_gateways(**p)),
    ("network", "get_service_gateway"): ("read", lambda c, p: c.get_service_gateway(**p)),
    ("network", "delete_service_gateway"): ("write", lambda c, p: c.delete_service_gateway(**p)),
    ("network", "list_local_peering_gateways"): ("read", lambda c, p: c.list_local_peering_gateways(**p)),
    ("network", "get_local_peering_gateway"): ("read", lambda c, p: c.get_local_peering_gateway(**p)),
    ("network", "delete_local_peering_gateway"): ("write", lambda c, p: c.delete_local_peering_gateway(**p)),
    ("network", "list_route_tables"): ("read", lambda c, p: c.list_route_tables(**p)),
    ("network", "get_route_table"): ("read", lambda c, p: c.get_route_table(**p)),
    ("network", "delete_route_table"): ("write", lambda c, p: c.delete_route_table(**p)),
    ("network", "list_security_lists"): ("read", lambda c, p: c.list_security_lists(**p)),
    ("network", "get_security_list"): ("read", lambda c, p: c.get_security_list(**p)),
    ("network", "delete_security_list"): ("write", lambda c, p: c.delete_security_list(**p)),
    ("network", "list_dhcp_options"): ("read", lambda c, p: c.list_dhcp_options(**p)),
    ("network", "get_dhcp_options"): ("read", lambda c, p: c.get_dhcp_options(**p)),
    ("network", "delete_dhcp_options"): ("write", lambda c, p: c.delete_dhcp_options(**p)),
    ("network", "list_network_security_groups"): ("read", lambda c, p: c.list_network_security_groups(**p)),
    ("network", "get_network_security_group"): ("read", lambda c, p: c.get_network_security_group(**p)),
    ("network", "delete_network_security_group"): ("write", lambda c, p: c.delete_network_security_group(**p)),
    ("network", "update_route_table"): ("write", lambda c, p: c.update_route_table(**p)),
    ("network", "get_vnic"): ("read", lambda c, p: c.get_vnic(**p)),
    ("network", "list_network_security_group_vnics"): ("read", lambda c, p: c.list_network_security_group_vnics(**p)),
    ("network", "list_private_ips"): ("read", lambda c, p: c.list_private_ips(**p)),
    ("blockstorage", "list_volumes"): ("read", lambda c, p: c.list_volumes(**p)),
    ("blockstorage", "get_volume"): ("read", lambda c, p: c.get_volume(**p)),
    ("blockstorage", "delete_volume"): ("write", lambda c, p: c.delete_volume(**p)),
    ("blockstorage", "list_boot_volumes"): ("read", lambda c, p: c.list_boot_volumes(**p)),
    ("blockstorage", "get_boot_volume"): ("read", lambda c, p: c.get_boot_volume(**p)),
    ("blockstorage", "delete_boot_volume"): ("write", lambda c, p: c.delete_boot_volume(**p)),
    ("blockstorage", "list_volume_backups"): ("read", lambda c, p: c.list_volume_backups(**p)),
    ("blockstorage", "get_volume_backup"): ("read", lambda c, p: c.get_volume_backup(**p)),
    ("blockstorage", "delete_volume_backup"): ("write", lambda c, p: c.delete_volume_backup(**p)),
    ("blockstorage", "list_boot_volume_backups"): ("read", lambda c, p: c.list_boot_volume_backups(**p)),
    ("blockstorage", "get_boot_volume_backup"): ("read", lambda c, p: c.get_boot_volume_backup(**p)),
    ("blockstorage", "delete_boot_volume_backup"): ("write", lambda c, p: c.delete_boot_volume_backup(**p)),
    ("object_storage", "get_namespace"): ("read", lambda c, p: c.get_namespace(**p)),
    ("object_storage", "list_buckets"): ("read", lambda c, p: c.list_buckets(**p)),
    ("object_storage", "get_bucket"): ("read", lambda c, p: c.get_bucket(**p)),
    ("object_storage", "list_objects"): ("read", lambda c, p: c.list_objects(**p)),
    ("object_storage", "list_object_versions"): ("read", lambda c, p: c.list_object_versions(**p)),
    ("object_storage", "list_multipart_uploads"): ("read", lambda c, p: c.list_multipart_uploads(**p)),
    ("object_storage", "delete_object"): ("write", lambda c, p: c.delete_object(**p)),
    ("object_storage", "abort_multipart_upload"): ("write", lambda c, p: c.abort_multipart_upload(**p)),
    ("object_storage", "delete_bucket"): ("write", lambda c, p: c.delete_bucket(**p)),
    ("object_storage", "list_retention_rules"): ("read", lambda c, p: c.list_retention_rules(**p)),
    ("object_storage", "list_replication_policies"): ("read", lambda c, p: c.list_replication_policies(**p)),
    ("load_balancer", "list_load_balancers"): ("read", lambda c, p: c.list_load_balancers(**p)),
    ("load_balancer", "get_load_balancer"): ("read", lambda c, p: c.get_load_balancer(**p)),
    ("load_balancer", "delete_load_balancer"): ("write", lambda c, p: c.delete_load_balancer(**p)),
    ("load_balancer", "get_work_request"): ("read", lambda c, p: c.get_work_request(**p)),
    ("network_load_balancer", "list_network_load_balancers"): ("read", lambda c, p: c.list_network_load_balancers(**p)),
    ("network_load_balancer", "get_network_load_balancer"): ("read", lambda c, p: c.get_network_load_balancer(**p)),
    ("network_load_balancer", "delete_network_load_balancer"): ("write", lambda c, p: c.delete_network_load_balancer(**p)),
    ("network_load_balancer", "get_work_request"): ("read", lambda c, p: c.get_work_request(**p)),
    ("certificates", "list_certificates"): ("read", lambda c, p: c.list_certificates(**p)),
    ("certificates", "get_certificate"): ("read", lambda c, p: c.get_certificate(**p)),
    ("certificates", "list_certificate_authorities"): ("read", lambda c, p: c.list_certificate_authorities(**p)),
    ("certificates", "get_certificate_authority"): ("read", lambda c, p: c.get_certificate_authority(**p)),
    ("certificates", "list_ca_bundles"): ("read", lambda c, p: c.list_ca_bundles(**p)),
    ("certificates", "get_ca_bundle"): ("read", lambda c, p: c.get_ca_bundle(**p)),
    ("certificates", "delete_ca_bundle"): ("write", lambda c, p: c.delete_ca_bundle(**p)),
    ("certificates", "list_associations"): ("read", lambda c, p: c.list_associations(**p)),
    ("certificates", "schedule_certificate_deletion"): ("write", lambda c, p: c.schedule_certificate_deletion(**p)),
    ("certificates", "schedule_certificate_authority_deletion"): ("write", lambda c, p: c.schedule_certificate_authority_deletion(**p)),
    ("kms_vault", "list_vaults"): ("read", lambda c, p: c.list_vaults(**p)),
    ("kms_vault", "get_vault"): ("read", lambda c, p: c.get_vault(**p)),
    ("kms_vault", "list_vault_replicas"): ("read", lambda c, p: c.list_vault_replicas(**p)),
    ("kms_vault", "schedule_vault_deletion"): ("write", lambda c, p: c.schedule_vault_deletion(**p)),
    ("kms_vault", "get_vault_usage"): ("read", lambda c, p: c.get_vault_usage(**p)),
    ("kms_management", "list_keys"): ("read", lambda c, p: c.list_keys(**p)),
    ("kms_management", "get_key"): ("read", lambda c, p: c.get_key(**p)),
    ("kms_management", "schedule_key_deletion"): ("write", lambda c, p: c.schedule_key_deletion(**p)),
    ("vault", "list_secrets"): ("read", lambda c, p: c.list_secrets(**p)),
    ("vault", "get_secret"): ("read", lambda c, p: c.get_secret(**p)),
    ("vault", "schedule_secret_deletion"): ("write", lambda c, p: c.schedule_secret_deletion(**p)),
    ("log_analytics", "list_namespaces"): ("read", lambda c, p: c.list_namespaces(**p)),
    ("log_analytics", "list_log_analytics_entities"): ("read", lambda c, p: c.list_log_analytics_entities(**p)),
    ("log_analytics", "get_log_analytics_entity"): ("read", lambda c, p: c.get_log_analytics_entity(**p)),
    ("log_analytics", "delete_log_analytics_entity"): ("write", lambda c, p: c.delete_log_analytics_entity(**p)),
    ("log_analytics", "list_entity_associations"): ("read", lambda c, p: c.list_entity_associations(**p)),
    ("log_analytics", "list_entity_source_associations"): ("read", lambda c, p: c.list_entity_source_associations(**p)),
    ("log_analytics", "list_log_analytics_object_collection_rules"): ("read", lambda c, p: c.list_log_analytics_object_collection_rules(**p)),
    ("log_analytics", "get_log_analytics_object_collection_rule"): ("read", lambda c, p: c.get_log_analytics_object_collection_rule(**p)),
    ("log_analytics", "delete_log_analytics_object_collection_rule"): ("write", lambda c, p: c.delete_log_analytics_object_collection_rule(**p)),
    ("log_analytics", "list_log_analytics_em_bridges"): ("read", lambda c, p: c.list_log_analytics_em_bridges(**p)),
    ("log_analytics", "get_log_analytics_em_bridge"): ("read", lambda c, p: c.get_log_analytics_em_bridge(**p)),
    ("log_analytics", "delete_log_analytics_em_bridge"): ("write", lambda c, p: c.delete_log_analytics_em_bridge(**p)),
    ("service_connector", "list_service_connectors"): ("read", lambda c, p: c.list_service_connectors(**p)),
    ("service_connector", "get_service_connector"): ("read", lambda c, p: c.get_service_connector(**p)),
    ("service_connector", "delete_service_connector"): ("write", lambda c, p: c.delete_service_connector(**p)),
    ("identity", "delete_compartment"): ("write", lambda c, p: c.delete_compartment(**p)),
    ("search", "search_resources"): ("read", lambda c, p: c.search_resources(**p)),
}


class GatewayError(CleanupError):
    """Safe failure context. Absence and authorization errors are ambiguous."""
    observation_status = 'unresolved'

    def __init__(self, service, operation, status=None, code=None, request_id=None):
        self.service = service
        self.operation = operation
        self.status = status
        self.code = code
        self.request_id = request_id
        super().__init__(f'{service}.{operation} unresolved (HTTP {status or "unavailable"})')


def _normalize(value):
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items()}
    # Only SDK model attributes enter the result; arbitrary objects are rejected.
    if hasattr(value, 'swagger_types') and hasattr(value, 'attribute_map'):
        return _normalize(oci.util.to_dict(value))
    raise CleanupError('Unsupported SDK response shape')


class Gateway:
    def __init__(self, config: dict, signer=None):
        self._config = dict(config)
        self.signer = signer
        self.tenancy_id = config.get('tenancy')
        self.bootstrap_region = config.get('region')
        if not self.tenancy_id or not self.bootstrap_region:
            raise CleanupError('Authentication requires tenancy and bootstrap region')
        self.home_region = None
        self.regions = []
        self.compartment_links = {}
        self.cleanup_scope = set()
        self.compartment_records = {}
        self._clients = {}
        self._vault_endpoints = {}
        self._read_retry = oci.retry.RetryStrategyBuilder(
            max_attempts_check=True, max_attempts=3,
            total_elapsed_time_check=True, total_elapsed_time_seconds=20,
            max_wait_between_calls_seconds=5).get_retry_strategy()

    def client(self, service: str, region: str, endpoint: str | None = None) -> object:
        if not isinstance(region, str) or not region:
            raise CleanupError('A region is required')
        if endpoint is not None:
            if service != 'kms_management' or (region, endpoint) not in self._vault_endpoints:
                raise CleanupError('Endpoint requires a freshly verified vault response')
        elif service == 'kms_management':
            raise CleanupError('KMS management requires a freshly verified vault endpoint')
        key = (service, region, endpoint)
        if key in self._clients:
            return self._clients[key]
        config = dict(self._config, region=region)
        kwargs = {'timeout': (10, 60), 'retry_strategy': oci.retry.NoneRetryStrategy()}
        if self.signer is not None:
            kwargs['signer'] = self.signer
        # Explicit factories preserve the service surface independently of plan input.
        factories = {
            'identity': oci.identity.IdentityClient,
            'search': oci.resource_search.ResourceSearchClient,
            'compute': oci.core.ComputeClient,
            'compute_management': oci.core.ComputeManagementClient,
            'container_engine': oci.container_engine.ContainerEngineClient,
            'network': oci.core.VirtualNetworkClient,
            'dns': oci.dns.DnsClient,
            'blockstorage': oci.core.BlockstorageClient,
            'object_storage': oci.object_storage.ObjectStorageClient,
            'load_balancer': oci.load_balancer.LoadBalancerClient,
            'network_load_balancer': oci.network_load_balancer.NetworkLoadBalancerClient,
            'certificates': oci.certificates_management.CertificatesManagementClient,
            'kms_vault': oci.key_management.KmsVaultClient,
            'kms_management': oci.key_management.KmsManagementClient,
            'vault': oci.vault.VaultsClient,
            'log_analytics': oci.log_analytics.LogAnalyticsClient,
            'service_connector': oci.sch.ServiceConnectorClient,
        }
        if service not in factories:
            raise CleanupError('Unsupported OCI service')
        if endpoint is not None:
            kwargs['service_endpoint'] = endpoint
        try:
            client = factories[service](config, **kwargs)
        except Exception:
            raise GatewayError(service, 'construct_client') from None
        self._clients[key] = client
        return client

    def _call(self, mode, service, region, operation, params, endpoint):
        contract = _OPERATIONS.get((service, operation))
        if contract is None or contract[0] != mode:
            raise CleanupError('Unsupported OCI operation or access mode')
        if type(params) is not dict or 'retry_strategy' in params:
            raise CleanupError('Operation parameters cannot override retry policy')
        kwargs = dict(params, retry_strategy=self._read_retry if mode == 'read' else oci.retry.NoneRetryStrategy())
        if service == 'kms_vault' and operation == 'get_vault':
            self._vault_endpoints = {k: v for k, v in self._vault_endpoints.items()
                                     if v != params.get('vault_id')}
        client = self.client(service, region, endpoint)
        try:
            response = contract[1](client, kwargs)
        except oci.exceptions.ServiceError as error:
            raise GatewayError(service, operation, error.status, error.code,
                               (error.headers or {}).get('opc-request-id')) from None
        except Exception:
            raise GatewayError(service, operation) from None
        data = _normalize(response.data)
        headers = {str(k).lower(): v for k, v in response.headers.items()}
        if service == 'kms_vault' and operation == 'get_vault':
            self._remember_vault(region, params, data)
        return data, headers

    def _remember_vault(self, region, params, vault):
        vault_id = params.get('vault_id')
        # Invalidate the previous proof before accepting another live response.
        self._vault_endpoints = {k: v for k, v in self._vault_endpoints.items() if v != vault_id}
        if not isinstance(vault, dict) or vault.get('id') != vault_id:
            raise CleanupError('Vault response identity does not match requested vault')
        parts = vault_id.split('.')
        realm = oci.regions.REGION_REALMS.get(region)
        domain = oci.regions.REALMS.get(realm)
        if (len(parts) < 5 or parts[:2] != ['ocid1', 'vault'] or parts[2] != realm
                or oci.regions.REGIONS_SHORT_NAMES.get(parts[3], parts[3]) != region or not domain):
            raise CleanupError('Vault identity does not match current region and realm')
        endpoint = vault.get('management_endpoint')
        if vault.get('lifecycle_state') == 'DELETED':
            return
        if not isinstance(endpoint, str):
            raise CleanupError('Vault has no management endpoint')
        parsed = urlsplit(endpoint)
        suffix = f'.kms.{region}.{domain}'
        if (parsed.scheme != 'https' or not parsed.hostname or not parsed.hostname.endswith(suffix)
                or not parsed.hostname[:-len(suffix)].endswith('-management')
                or parsed.username or parsed.password or parsed.port is not None
                or parsed.path or parsed.query or parsed.fragment):
            raise CleanupError('Vault endpoint does not match the OCI region realm')
        self._vault_endpoints[(region, endpoint)] = vault_id

    def read(self, service: str, region: str, operation: str, params: dict,
             endpoint: str | None = None) -> tuple[dict, dict]:
        return self._call('read', service, region, operation, params, endpoint)

    def write(self, service: str, region: str, operation: str, params: dict,
              endpoint: str | None = None) -> tuple[dict, dict]:
        return self._call('write', service, region, operation, params, endpoint)

    def items(self, service: str, region: str, operation: str, params: dict,
              endpoint: str | None = None) -> list[dict]:
        """All pages or an error: a denied page never yields a partial inventory."""
        values = []
        kwargs = dict(params)
        object_listing = (service, operation) == ('object_storage', 'list_objects')
        seen = set()
        initial_token = kwargs.get('start' if object_listing else 'page')
        if initial_token:
            seen.add(initial_token)
        while True:
            data, headers = self.read(service, region, operation, kwargs, endpoint)
            if isinstance(data, list):
                page_values = data
            elif isinstance(data, dict):
                page_values = data.get('objects' if object_listing else 'items')
            else:
                page_values = None
            if not isinstance(page_values, list) or any(not isinstance(v, dict) for v in page_values):
                raise CleanupError('Expected SDK list or collection response')
            values.extend(page_values)
            token = data.get('next_start_with') if object_listing else headers.get('opc-next-page')
            if not token:
                return values
            if not isinstance(token, str) or token in seen:
                raise CleanupError('Invalid or repeated OCI pagination token')
            seen.add(token)
            kwargs['start' if object_listing else 'page'] = token


def build_gateway(auth: str, config_file: str, profile: str, bootstrap_region: str | None) -> Gateway:
    try:
        if auth == 'api_key':
            config = oci.config.from_file(config_file, profile)
            oci.config.validate_config(config)
            if bootstrap_region:
                config = dict(config, region=bootstrap_region)
            signer = None
        elif auth == 'instance_principal':
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
            config = {'region': bootstrap_region or signer.region, 'tenancy': signer.tenancy_id}
        else:
            raise CleanupError('Unsupported authentication mode')
    except CleanupError:
        raise
    except Exception:
        raise CleanupError('OCI authentication configuration could not be loaded') from None
    return Gateway(config, signer)


def discover_scope(gateway: Gateway, parent_id: str) -> tuple[str, str, list[str], dict[str, str]]:
    """Validate actual IAM links from tenancy root, then select the retained subtree."""
    tenancy = gateway.tenancy_id
    if parent_id == tenancy or not isinstance(parent_id, str) or not parent_id.startswith('ocid1.compartment.'):
        raise CleanupError('Retained parent must be a non-root compartment OCID')
    subscriptions = gateway.items('identity', gateway.bootstrap_region, 'list_region_subscriptions', {'tenancy_id': tenancy})
    homes = [s.get('region_name') for s in subscriptions if s.get('is_home_region') is True]
    regions = sorted({s.get('region_name') for s in subscriptions if isinstance(s.get('region_name'), str) and s.get('region_name')})
    if len(homes) != 1 or homes[0] not in regions:
        raise CleanupError('Cannot establish one subscribed tenancy home region')
    home = homes[0]
    rows = gateway.items('identity', home, 'list_compartments', {
        'compartment_id': tenancy, 'access_level': 'ANY', 'compartment_id_in_subtree': True})
    links = {}
    records = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise CleanupError("Malformed compartment response")
        if row["id"] in records:
            raise CleanupError("Duplicate compartment identity")
        records[row["id"]] = dict(row)
        if row.get('lifecycle_state') == 'DELETED':
            continue
        child, parent = row.get('id'), row.get('compartment_id')
        if (not isinstance(child, str) or not child.startswith('ocid1.compartment.')
                or not isinstance(parent, str) or not parent or child == parent
                or child in links):
            raise CleanupError('Malformed or conflicting compartment parent link')
        links[child] = parent
    # Validate every visible chain. A hidden ancestor leaves scope unproven.
    verified = {tenancy}
    for child in links:
        chain = set()
        current = child
        while current not in verified:
            if current in chain or current not in links:
                raise CleanupError('Compartment hierarchy is cyclic or has a hidden parent')
            chain.add(current)
            current = links[current]
        verified.update(chain)
    if parent_id not in links:
        raise CleanupError('Retained compartment is not reachable from authenticated tenancy')
    live, _ = gateway.read('identity', home, 'get_compartment', {'compartment_id': parent_id})
    if (live.get('id') != parent_id or live.get('compartment_id') != links[parent_id]
            or live.get('lifecycle_state') != 'ACTIVE'):
        raise CleanupError('Retained compartment is inactive or live parent link changed')
    descendants = {parent_id}
    children = {}
    for child, parent in links.items():
        children.setdefault(parent, []).append(child)
    pending = [parent_id]
    while pending:
        for child in children.get(pending.pop(), []):
            descendants.add(child)
            pending.append(child)
    gateway.cleanup_scope = set(descendants)
    gateway.compartment_links = dict(links)
    gateway.compartment_records = records
    gateway.home_region = home
    gateway.regions = regions
    return tenancy, home, regions, {child: links[child] for child in links if child in descendants}
