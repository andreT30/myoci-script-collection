"""Gateway behavior and installed SDK contracts; never contacts OCI."""
import inspect
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import oci
from compartment_cleanup.gateway import Gateway, GatewayError, build_gateway, discover_scope
from compartment_cleanup.model import CleanupError, Node
from simulator import Simulator

R = 'eu-frankfurt-1'
T = 'ocid1.tenancy.oc1..tenancy'
P = 'ocid1.compartment.oc1..parent'
C = 'ocid1.compartment.oc1..child'
U = 'ocid1.compartment.oc1..unrelated'


def response(data, headers=None):
    return SimpleNamespace(data=data, headers=headers or {})


class Pages:
    def __init__(self, values):
        self.values = iter(values)
        self.calls = []

    def call(self, **params):
        self.calls.append(params)
        value = next(self.values)
        if isinstance(value, Exception):
            raise value
        return value

    list_compartments = call
    list_bulk_action_resource_types = call
    list_objects = call
    get_compartment = call
    delete_compartment = call
    get_vault = call
    get_key = call
    search_resources = call
    list_object_versions = call


class Scope:
    tenancy_id = T
    bootstrap_region = R

    def __init__(self, rows=None):
        self.rows = rows if rows is not None else [
            {'id': P, 'compartment_id': T, 'lifecycle_state': 'ACTIVE'},
            {'id': C, 'compartment_id': P, 'lifecycle_state': 'ACTIVE'},
            {'id': U, 'compartment_id': T, 'lifecycle_state': 'ACTIVE'}]
        self.calls = []

    def read(self, service, region, operation, params):
        return {'id': P, 'compartment_id': T, 'lifecycle_state': 'ACTIVE'}, {}

    def items(self, service, region, operation, params):
        self.calls.append((operation, params))
        if operation == 'list_region_subscriptions':
            return [{'region_name': R, 'is_home_region': True, 'status': 'READY'},
                    {'region_name': 'uk-london-1', 'is_home_region': False, 'status': 'READY'}]
        return self.rows


class GatewayTests(unittest.TestCase):
    def gateway(self, fake, service='identity'):
        gateway = Gateway({'tenancy': T, 'region': R})
        gateway._clients[(service, R, None)] = fake
        return gateway

    def test_api_key_forwards_configuration_and_profile_without_copying_key(self):
        config = {'tenancy': T, 'region': R, 'key_file': '/private/key.pem'}
        with patch('oci.config.from_file', return_value=config) as load, patch('oci.config.validate_config') as validate:
            gateway = build_gateway('api_key', '/chosen/config', 'SPECIAL', None)
        load.assert_called_once_with('/chosen/config', 'SPECIAL')
        validate.assert_called_once_with(config)
        self.assertEqual(gateway.tenancy_id, T)
        self.assertNotIn('key_file', gateway.__repr__())

    def test_instance_principal_constructs_signer_and_bootstrap_override(self):
        signer = SimpleNamespace(region=R, tenancy_id=T)
        with patch('oci.auth.signers.InstancePrincipalsSecurityTokenSigner', return_value=signer):
            gateway = build_gateway('instance_principal', 'unused', 'unused', 'uk-london-1')
        self.assertIs(gateway.signer, signer)
        self.assertEqual(gateway.bootstrap_region, 'uk-london-1')

    def test_explicit_factory_caches_by_region_and_uses_timeouts(self):
        gateway = Gateway({'tenancy': T, 'region': R})
        with patch('oci.identity.IdentityClient') as factory:
            self.assertIs(gateway.client('identity', R), gateway.client('identity', R))
        self.assertEqual(factory.call_count, 1)
        self.assertEqual(factory.call_args.kwargs['timeout'], (10, 60))

    def test_unknown_auth_service_and_operation_rejected(self):
        with self.assertRaises(CleanupError):
            build_gateway('other', '', '', None)
        gateway = Gateway({'tenancy': T, 'region': R})
        with self.assertRaises(CleanupError):
            gateway.client('__import__', R)
        with self.assertRaises(CleanupError):
            gateway.read('identity', R, 'delete_compartment', {'compartment_id': P})
        with self.assertRaises(CleanupError):
            gateway.write('identity', R, 'get_compartment', {'compartment_id': P})

    def test_list_pages_normalize_models_and_lowercase_headers(self):
        fake = Pages([response([oci.identity.models.Compartment(id=P)], {'Opc-Next-Page': 'two'}),
                      response([oci.identity.models.Compartment(id=C)])])
        values = self.gateway(fake).items('identity', R, 'list_compartments', {'compartment_id': T})
        self.assertEqual([v['id'] for v in values], [P, C])
        self.assertEqual(fake.calls[1]['page'], 'two')
        self.assertNotIn('page', fake.calls[0])

    def test_collection_pages_and_object_versions(self):
        fake = Pages([response(oci.identity.models.BulkActionResourceTypeCollection(items=[
            oci.identity.models.BulkActionResourceType(name='Instance', metadata_keys=['availabilityDomain'])]))])
        values = self.gateway(fake).items('identity', R, 'list_bulk_action_resource_types', {'bulk_action_type': 'BULK_DELETE_RESOURCES'})
        self.assertEqual(values, [{'name': 'Instance', 'metadata_keys': ['availabilityDomain']}])

    def test_denied_second_page_never_returns_partial_inventory(self):
        fake = Pages([response([{'id': P}], {'opc-next-page': 'two'}),
                      oci.exceptions.ServiceError(403, 'NotAuthorized', {}, 'sensitive service message')])
        with self.assertRaises(GatewayError) as caught:
            self.gateway(fake).items('identity', R, 'list_compartments', {'compartment_id': T})
        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(caught.exception.observation_status, 'unresolved')
        self.assertNotIn('sensitive', str(caught.exception))

    def test_repeated_page_token_rejected(self):
        fake = Pages([response([], {'opc-next-page': 'same'}), response([], {'opc-next-page': 'same'})])
        with self.assertRaises(CleanupError):
            self.gateway(fake).items('identity', R, 'list_compartments', {'compartment_id': T})

    def test_object_listing_uses_start_and_next_start_with(self):
        fake = Pages([response(oci.object_storage.models.ListObjects(objects=[oci.object_storage.models.ObjectSummary(name='a')], next_start_with='b')),
                      response(oci.object_storage.models.ListObjects(objects=[oci.object_storage.models.ObjectSummary(name='b')]))])
        values = self.gateway(fake, 'object_storage').items('object_storage', R, 'list_objects', {'namespace_name': 'ns', 'bucket_name': 'bucket'})
        self.assertEqual([v['name'] for v in values], ['a', 'b'])
        self.assertEqual(fake.calls[1]['start'], 'b')
        self.assertNotIn('page', fake.calls[1])

    def test_mutation_retry_disabled_and_caller_cannot_override(self):
        fake = Pages([response(None, {'Opc-Workrequest-Id': 'work'})])
        gateway = self.gateway(fake)
        data, headers = gateway.write('identity', R, 'delete_compartment', {'compartment_id': C})
        self.assertIsNone(data)
        self.assertEqual(headers['opc-workrequest-id'], 'work')
        self.assertIsInstance(fake.calls[0]['retry_strategy'], oci.retry.NoneRetryStrategy)
        with self.assertRaises(CleanupError):
            gateway.write('identity', R, 'delete_compartment', {'compartment_id': C, 'retry_strategy': object()})

    def test_ambiguous_404_and_timeout_are_unresolved(self):
        for error in [oci.exceptions.ServiceError(404, 'NotAuthorizedOrNotFound', {}, 'hidden'), TimeoutError('timeout')]:
            with self.subTest(error=type(error).__name__), self.assertRaises(GatewayError) as caught:
                self.gateway(Pages([error])).read('identity', R, 'get_compartment', {'compartment_id': P})
            self.assertEqual(caught.exception.observation_status, 'unresolved')

    def test_read_retry_is_bounded(self):
        fake = Pages([response({'id': P})])
        self.gateway(fake).read('identity', R, 'get_compartment', {'compartment_id': P})
        strategy = fake.calls[0]['retry_strategy']
        calls = []
        def failing():
            calls.append(1)
            raise oci.exceptions.ServiceError(500, 'InternalError', {}, 'failed')
        with patch('oci.retry.retry.time.sleep'), self.assertRaises(oci.exceptions.ServiceError):
            strategy.make_retrying_call(failing)
        self.assertEqual(len(calls), 3)

    def test_endpoint_requires_fresh_matching_vault_and_realm(self):
        vault_id = 'ocid1.vault.oc1.eu-frankfurt-1.unique'
        endpoint = 'https://unique-management.kms.eu-frankfurt-1.oraclecloud.com'
        gateway = self.gateway(Pages([response({'id': vault_id, 'management_endpoint': endpoint})]), 'kms_vault')
        with self.assertRaises(CleanupError):
            gateway.client('kms_management', R, endpoint)
        gateway.read('kms_vault', R, 'get_vault', {'vault_id': vault_id})
        with patch('oci.key_management.KmsManagementClient') as factory:
            gateway.client('kms_management', R, endpoint)
            self.assertEqual(factory.call_args.kwargs['service_endpoint'], endpoint)
        for invalid in ['https://unique-management.kms.eu-frankfurt-1.attacker.com', endpoint + '/path', 'http://' + endpoint[8:]]:
            with self.assertRaises(CleanupError):
                gateway.client('kms_management', R, invalid)

    def test_search_uses_sdk_structured_details_and_collection(self):
        query = oci.resource_search.models.StructuredSearchDetails(query='query all resources')
        fake = Pages([response(oci.resource_search.models.ResourceSummaryCollection(items=[
            oci.resource_search.models.ResourceSummary(identifier='resource', resource_type='Instance')]))])
        values = self.gateway(fake, 'search').items('search', R, 'search_resources', {'search_details': query})
        self.assertEqual(values[0]['identifier'], 'resource')
        self.assertIs(fake.calls[0]['search_details'], query)

    def test_object_versions_use_page_and_items(self):
        fake = Pages([response(oci.object_storage.models.ObjectVersionCollection(items=[
            oci.object_storage.models.ObjectVersionSummary(name='a', version_id='version1')]), {'opc-next-page': 'two'}),
            response(oci.object_storage.models.ObjectVersionCollection(items=[
                oci.object_storage.models.ObjectVersionSummary(name='a', version_id='version2')]))])
        values = self.gateway(fake, 'object_storage').items('object_storage', R, 'list_object_versions',
            {'namespace_name': 'ns', 'bucket_name': 'bucket'})
        self.assertEqual([v['version_id'] for v in values], ['version1', 'version2'])
        self.assertEqual(fake.calls[1]['page'], 'two')

    def test_failed_vault_refresh_revokes_old_endpoint_proof(self):
        vault_id = 'ocid1.vault.oc1.fra.unique'
        endpoint = 'https://unique-management.kms.eu-frankfurt-1.oraclecloud.com'
        fake = Pages([response({'id': vault_id, 'management_endpoint': endpoint}),
                      oci.exceptions.ServiceError(404, 'NotAuthorizedOrNotFound', {}, 'hidden')])
        gateway = self.gateway(fake, 'kms_vault')
        gateway.read('kms_vault', R, 'get_vault', {'vault_id': vault_id})
        with self.assertRaises(GatewayError):
            gateway.read('kms_vault', R, 'get_vault', {'vault_id': vault_id})
        with self.assertRaisesRegex(CleanupError, 'freshly verified'):
            gateway.client('kms_management', R, endpoint)

    def test_terminal_vault_read_does_not_require_a_management_endpoint(self):
        vault_id = 'ocid1.vault.oc1.fra.unique'
        fake = Pages([response({'id': vault_id, 'lifecycle_state': 'DELETED', 'management_endpoint': None})])
        data, _ = self.gateway(fake, 'kms_vault').read('kms_vault', R, 'get_vault', {'vault_id': vault_id})
        self.assertEqual(data['lifecycle_state'], 'DELETED')

    def test_scope_preserves_deleted_compartment_evidence(self):
        gateway = Scope()
        gateway.rows.append({'id': 'ocid1.compartment.oc1..deleted', 'compartment_id': P, 'lifecycle_state': 'DELETED'})
        _, _, _, links = discover_scope(gateway, P)
        self.assertNotIn('ocid1.compartment.oc1..deleted', links)
        self.assertEqual(gateway.compartment_records['ocid1.compartment.oc1..deleted']['lifecycle_state'], 'DELETED')

    def test_scope_follows_links_and_retains_full_visible_hierarchy(self):
        gateway = Scope()
        tenancy, home, regions, links = discover_scope(gateway, P)
        self.assertEqual((tenancy, home, regions), (T, R, [R, 'uk-london-1']))
        self.assertEqual(links, {P: T, C: P})
        self.assertEqual(gateway.compartment_links[U], T)
        self.assertEqual(gateway.calls[1][1], {'compartment_id': T, 'access_level': 'ANY', 'compartment_id_in_subtree': True})

    def test_tenancy_target_hidden_parent_cycles_and_conflicts_rejected(self):
        with self.assertRaises(CleanupError):
            discover_scope(Scope(), T)
        invalid_rows = [
            [{'id': P, 'compartment_id': 'hidden', 'lifecycle_state': 'ACTIVE'}],
            [{'id': P, 'lifecycle_state': 'ACTIVE'}],
            [{'id': P, 'compartment_id': C}, {'id': C, 'compartment_id': P}],
            [{'id': P, 'compartment_id': T}, {'id': P, 'compartment_id': U}],
            [{'id': P, 'compartment_id': T}, {'id': C, 'compartment_id': 'hidden'}],
        ]
        for rows in invalid_rows:
            with self.subTest(rows=rows), self.assertRaises(CleanupError):
                discover_scope(Scope(rows), P)

    def test_scope_includes_subscribed_region_still_initializing(self):
        gateway = Scope()
        original_items = gateway.items
        def items(service, region, operation, params):
            if operation == 'list_region_subscriptions':
                return [{'region_name': R, 'is_home_region': True, 'status': 'READY'},
                        {'region_name': 'uk-london-1', 'is_home_region': False, 'status': 'IN_PROGRESS'}]
            return original_items(service, region, operation, params)
        gateway.items = items
        self.assertEqual(discover_scope(gateway, P)[2], [R, 'uk-london-1'])

    def test_sdk_contracts_for_scope_search_and_list_shapes(self):
        self.assertIn('compartment_id', inspect.signature(oci.identity.IdentityClient.get_compartment).parameters)
        self.assertIn('tenancy_id', inspect.signature(oci.identity.IdentityClient.list_region_subscriptions).parameters)
        query = oci.resource_search.models.StructuredSearchDetails(query='query all resources')
        self.assertEqual(oci.util.to_dict(query)['type'], 'Structured')
        self.assertIn('next_start_with', oci.object_storage.models.ListObjects().attribute_map)
        self.assertIn('items', oci.object_storage.models.ObjectVersionCollection().attribute_map)

    def test_simulator_resources_permissions_pages_and_scheduled_clock(self):
        sim = Simulator(T, R, {P: T, C: P})
        node = Node('resource', 'Example', R, C, '', 'ACTIVE', 'example', 'delete', {})
        sim.add(node)
        self.assertEqual(sim.discover_scope(P)[3], {P: T, C: P})
        sim.set_pages('identity', R, 'list_compartments', [([{'id': C}], {})])
        self.assertEqual(sim.items('identity', R, 'list_compartments', {'compartment_id': P}), [{'id': C}])
        sim.deny('identity', R, 'get_compartment', 403)
        with self.assertRaises(GatewayError):
            sim.read('identity', R, 'get_compartment', {'compartment_id': P})
        sim.schedule('resource', datetime(2026, 10, 10, tzinfo=timezone.utc), 'work')
        self.assertEqual(sim.work_requests['work']['status'], 'IN_PROGRESS')
        sim.advance(datetime(2026, 10, 11, tzinfo=timezone.utc))
        self.assertEqual(sim.resources['resource'].lifecycle_state, 'DELETED')
        self.assertEqual(sim.work_requests['work']['status'], 'SUCCEEDED')
        self.assertTrue(sim.events)


if __name__ == '__main__':
    unittest.main()
