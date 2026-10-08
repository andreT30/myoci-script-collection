"""Offline core cleanup safety: scope, typed dependencies, and deletion evidence."""
from dataclasses import replace
import unittest
from types import SimpleNamespace
from unittest.mock import patch, Mock
import oci
from compartment_cleanup.gateway import Gateway, discover_scope
from compartment_cleanup.discovery import discover

from compartment_cleanup.model import CleanupError, Node, Edge
from compartment_cleanup.handlers.base import Registry
from simulator import Simulator
try:
    from compartment_cleanup.handlers.core import IAMPolicies, ComputeInstances, BlockBootVolumes
except ImportError:
    IAMPolicies = ComputeInstances = BlockBootVolumes = None

P, C, X, T = 'parent', 'child', 'external', 'tenancy'
R = 'region'


def resource(key, kind, owner=P, state='AVAILABLE', metadata=None):
    return Node(key, kind, R, owner, key, state, '', 'unresolved', metadata or {})


class CoreGateway(Simulator):
    def __init__(self):
        super().__init__(T, R, {P:T, C:P, X:T})
        self.cleanup_scope = {P,C}
        self.rows = {}
        self.etags = {}

    def items(self, service, region, operation, params, endpoint=None):
        self._event('items', service, region, operation, params, endpoint)
        if operation == 'list_availability_domains':
            return [{'name':'AD-one'}, {'name':'AD-two'}]
        rows = self.rows.get(operation, [])
        if isinstance(rows, Exception):
            raise rows
        return [dict(row) for row in rows if (operation == 'list_instance_pool_instances' or not params.get('compartment_id') or row.get('compartment_id') == params['compartment_id'])
                and (not params.get('instance_pool_id') or row.get('instance_pool_id') == params['instance_pool_id'])
                and (not params.get('vnic_id') or row.get('vnic_id') == params['vnic_id'])
                and (not params.get('scope') or row.get('scope') == params['scope'])
                and (not params.get('availability_domain') or row.get('availability_domain') == params['availability_domain'])]

    def read(self, service, region, operation, params, endpoint=None):
        data, headers = super().read(service, region, operation, params, endpoint)
        return data, dict(headers, etag=self.etags.get(data.get('id'), 'live-etag'))

    def add_row(self, node, operation):
        self.add(node)
        self.rows.setdefault(operation, []).append(dict(node.metadata, id=node.key,
            compartment_id=node.compartment_id, lifecycle_state=node.lifecycle_state, display_name=node.display_name))


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(IAMPolicies, 'Task 5A core handlers are required')
        self.g = CoreGateway()
        self.compute = ComputeInstances()
        self.volumes = BlockBootVolumes()
        self.policies = IAMPolicies()

    def test_registry_ignores_artifact_operation_and_secret_metadata(self):
        registry = Registry({'compute':self.compute, 'blockstorage':self.volumes, 'policies':self.policies})
        n = registry.classify(replace(resource('v','Volume',metadata={'kms_key_id':'k','chap_secret':'secret'}),
                                     handler='evil', action='schedule'))
        self.assertEqual((n.handler,n.action), ('blockstorage','delete'))
        self.assertEqual(n.metadata, {'kms_key_id':'k'})
        self.assertEqual(self.compute.bulk_resource_types, {})

    def test_policy_discovery_home_only_and_does_not_parse_statements(self):
        self.g.add_row(resource('p','Policy',state='ACTIVE',metadata={'statements':['allow ocid1.fake']}),'list_policies')
        nodes, edges, probes = self.policies.discover(self.g,P,R)
        self.assertEqual([n.key for n in nodes], ['p'])
        self.assertEqual((nodes[0].metadata,edges), ({},[]))
        self.assertTrue(all(p.status == 'complete' for p in probes))
        self.assertEqual(self.policies.discover(self.g,P,'other')[0], [])
        self.assertTrue(self.policies.late_action)

    def test_policy_fresh_etag_and_terminal_only(self):
        n = resource('p','Policy',state='ACTIVE')
        self.g.add(n)
        observation = self.policies.inspect(self.g,n,{P,C})
        self.assertEqual((observation.status,observation.etag), ('present','live-etag'))
        self.g.responses[('identity',R,'delete_policy')] = (None, {'opc-request-id':'request'})
        result = self.policies.submit(self.g,n,observation,'attempt')
        self.assertEqual(result.status,'pending')
        self.assertEqual(self.g.events[-1][4], {'policy_id':'p','if_match':'live-etag'})
        self.g.resources['p'] = replace(n,lifecycle_state='DELETING')
        self.assertEqual(self.policies.inspect(self.g,n,{P}).status,'pending')
        self.g.resources['p'] = replace(n,lifecycle_state='DELETED')
        self.assertEqual(self.policies.inspect(self.g,n,{P}).status,'deleted')

    def test_404_and_moved_owner_never_prove_removal(self):
        n = resource('v','Volume')
        self.assertEqual(self.volumes.inspect(self.g,n,{P}).status,'unresolved')
        self.g.add(replace(n,compartment_id=X))
        self.assertEqual(self.volumes.inspect(self.g,n,{P}).status,'moved')
        with self.assertRaises(CleanupError):
            self.volumes.submit(self.g,n,self.volumes.inspect(self.g,n,{P}),'attempt')
        self.assertFalse(any(e[0]=='write' for e in self.g.events))

    def test_changed_typed_reference_requires_refresh(self):
        n = resource('v','Volume',metadata={'kms_key_id':'old'})
        self.g.add(replace(n,metadata={'kms_key_id':'new'}))
        self.assertEqual(self.volumes.inspect(self.g,n,{P}).status,'unresolved')

    def test_volumes_backups_keep_key_refs_and_no_source_lineage_edges(self):
        self.g.add_row(resource('v','Volume',metadata={'kms_key_id':'key'}),'list_volumes')
        self.g.add_row(resource('b','VolumeBackup',metadata={'volume_id':'v','kms_key_id':'other'}),'list_volume_backups')
        nodes, edges, probes = self.volumes.discover(self.g,P,R)
        self.assertEqual({n.key for n in nodes},{'v','b'})
        self.assertEqual(edges,[])
        self.assertEqual(next(n for n in nodes if n.key=='v').metadata['kms_key_id'],'key')
        self.assertTrue(all(p.status=='complete' for p in probes))
        self.assertNotIn('volume_id',next(n for n in nodes if n.key=='b').metadata)
        self.assertFalse(any('availability_domain' in e[4] for e in self.g.events if 'backup' in e[3]))

    def test_boot_volume_data_attachment_outside_scope_blocks(self):
        n = resource('boot','BootVolume')
        self.g.add(n)
        self.g.add_row(resource('a','VolumeAttachment',X,'ATTACHED',{'instance_id':'i','volume_id':'boot','attachment_type':'paravirtualized'}),'list_volume_attachments')
        self.g.add(resource('i','Instance',X,'RUNNING'))
        self.assertEqual(self.volumes.inspect(self.g,n,{P,C}).status,'unresolved')
        compartments = {e[4]['compartment_id'] for e in self.g.events if e[3]=='list_volume_attachments'}
        self.assertEqual(compartments,{T,P,C,X})

    def test_failed_external_scan_blocks_volume(self):
        n = resource('v','Volume')
        self.g.add(n)
        self.g.rows['list_volume_attachments'] = CleanupError('denied')
        self.assertEqual(self.volumes.inspect(self.g,n,{P,C}).status,'unresolved')

    def test_active_inscope_attachment_orders_before_volume_and_prevents_early_delete(self):
        self.g.add_row(resource('v','Volume'),'list_volumes')
        self.g.add_row(resource('a','VolumeAttachment',C,'ATTACHED',{'instance_id':'i','volume_id':'v','attachment_type':'iscsi'}),'list_volume_attachments')
        self.g.add(resource('i','Instance',C,'RUNNING'))
        nodes,edges,_ = self.volumes.discover(self.g,P,R)
        self.assertIn(('a','v'),{(e.before,e.after) for e in edges})
        self.assertFalse(nodes[0].blockers)
        self.assertEqual(self.volumes.inspect(self.g,nodes[0],{P,C}).status,'unresolved')

    def test_clear_volume_deletion_uses_fresh_etag_and_pending_submission(self):
        n = resource('v','Volume')
        self.g.add(n)
        observation = self.volumes.inspect(self.g,n,{P,C})
        self.assertEqual(observation.status,'present')
        self.g.responses[('blockstorage',R,'delete_volume')] = (None,{})
        self.assertEqual(self.volumes.submit(self.g,n,observation,'attempt').status,'pending')
        self.assertEqual(self.g.events[-1][4],{'volume_id':'v','if_match':'live-etag'})

    def test_group_replica_and_locked_backups_remain_blocked(self):
        for field,value in [('volume_group_id','group'),('block_volume_replicas',[{'id':'r'}]),
                            ('is_auto_tune_enabled',False)]:
            n = resource('v','Volume',metadata={field:value})
            self.g.add(n)
            status = self.volumes.inspect(self.g,n,{P,C}).status
            self.assertEqual(status,'present' if field=='is_auto_tune_enabled' else 'unresolved')
        n=resource('b','VolumeBackup',metadata={'is_retention_lock_enabled':True})
        self.g.add(n)
        self.assertEqual(self.volumes.inspect(self.g,n,{P,C}).status,'unresolved')

    def test_failed_producer_evidence_is_explicitly_blocked(self):
        self.g.rows['list_instance_pools'] = CleanupError('denied')
        self.g.add_row(resource('i','Instance',state='RUNNING'),'list_instances')
        nodes,_,probes=self.compute.discover(self.g,P,R)
        self.assertTrue(nodes[0].blockers)
        self.assertTrue(any(p.status=='failed' and 'producer' in p.service for p in probes))
        self.assertEqual(self.compute.inspect(self.g,nodes[0],{P,C}).status,'unresolved')
        with self.assertRaises(CleanupError):
            self.compute.submit(self.g,nodes[0],self.compute.inspect(self.g,nodes[0],{P,C}),'attempt')

    def test_external_vnic_blocks_instance_and_is_not_returned_as_executable_node(self):
        self.g.add_row(resource('i','Instance',state='RUNNING'),'list_instances')
        self.g.add_row(resource('a','VnicAttachment',state='ATTACHED',metadata={'instance_id':'i','vnic_id':'nic'}),'list_vnic_attachments')
        self.g.add(resource('nic','Vnic',X,'AVAILABLE',{'subnet_id':'subnet'}))
        nodes,_,_=self.compute.discover(self.g,P,R)
        self.assertNotIn('nic',{n.key for n in nodes})
        instance=next(n for n in nodes if n.key=='i')
        self.assertTrue(any('VNIC' in b for b in instance.blockers))

    def test_boot_attachments_list_every_ad_and_have_distinct_nodes(self):
        self.g.add_row(resource('a','BootVolumeAttachment',state='ATTACHED',metadata={'instance_id':'i','boot_volume_id':'boot','availability_domain':'AD-two'}),'list_boot_volume_attachments')
        self.g.add(resource('i','Instance',state='RUNNING'))
        nodes,_,_=self.compute.discover(self.g,P,R)
        self.assertIn('a',{n.key for n in nodes})
        calls=[e for e in self.g.events if e[3]=='list_boot_volume_attachments']
        self.assertEqual({e[4]['availability_domain'] for e in calls},{'AD-one','AD-two'})
        n=next(n for n in nodes if n.key=='a')
        self.assertEqual(self.compute.inspect(self.g,n,{P,C}).status,'unresolved')

    def test_direct_block_detach_preserves_external_volume_and_rechecks_instance_scope(self):
        n=resource('a','VolumeAttachment',state='ATTACHED',metadata={'instance_id':'i','volume_id':'external-volume','attachment_type':'paravirtualized'})
        self.g.add(n)
        self.g.add(resource('i','Instance',state='RUNNING'))
        observation=self.compute.inspect(self.g,n,{P,C})
        self.assertEqual(observation.status,'present')
        self.g.responses[('compute',R,'detach_volume')]=(None,{})
        self.assertEqual(self.compute.submit(self.g,n,observation,'attempt').status,'pending')
        self.assertEqual(self.g.events[-1][4],{'volume_attachment_id':'a','if_match':'live-etag'})
        self.g.resources['i']=replace(self.g.resources['i'],compartment_id=X)
        self.assertEqual(self.compute.inspect(self.g,n,{P,C}).status,'unresolved')

    def test_unknown_attachment_type_and_boot_running_detach_block(self):
        n=resource('a','VolumeAttachment',state='ATTACHED',metadata={'instance_id':'i','volume_id':'v','attachment_type':'future'})
        self.g.add(n)
        self.g.add(resource('i','Instance',state='RUNNING'))
        self.assertEqual(self.compute.inspect(self.g,n,{P,C}).status,'unresolved')
        n=resource('b','BootVolumeAttachment',state='ATTACHED',metadata={'instance_id':'i','boot_volume_id':'boot','availability_domain':'AD-one'})
        self.g.add(n)
        self.assertEqual(self.compute.inspect(self.g,n,{P,C}).status,'unresolved')
        self.g.resources['i']=replace(self.g.resources['i'],lifecycle_state='STOPPED')
        self.assertEqual(self.compute.inspect(self.g,n,{P,C}).status,'present')

    def test_standalone_instance_termination_preserves_both_volume_families(self):
        self.g.add_row(resource('i','Instance',state='RUNNING'),'list_instances')
        nodes,_,probes=self.compute.discover(self.g,P,R)
        n=next(n for n in nodes if n.key=='i')
        self.assertFalse(n.blockers)
        self.assertTrue(all(p.status=='complete' for p in probes))
        observation=self.compute.inspect(self.g,n,{P,C})
        self.assertEqual(observation.status,'present')
        self.assertEqual(n.metadata['preserved_volume_ids'],[])
        self.g.responses[('compute',R,'terminate_instance')]=(None,{})
        self.assertEqual(self.compute.submit(self.g,n,observation,'attempt').status,'pending')
        self.assertEqual(self.g.events[-1][4],{'instance_id':'i','if_match':'live-etag',
            'preserve_boot_volume':True,'preserve_data_volumes_created_at_launch':True})

    def test_known_external_and_inscope_producers_block_member_termination(self):
        self.g.add_row(resource('i','Instance',state='RUNNING'),'list_instances')
        self.g.rows['list_instance_pools']=[{'id':'pool','compartment_id':X,'lifecycle_state':'RUNNING'}]
        self.g.rows['list_instance_pool_instances']=[{'id':'i','instance_pool_id':'pool','compartment_id':X}]
        nodes,_,_=self.compute.discover(self.g,P,R)
        self.assertTrue(next(n for n in nodes if n.key=='i').blockers)
        self.g.rows['list_instance_pools']=[]
        self.g.rows['list_node_pools']=[{'id':'pool','compartment_id':P,'lifecycle_state':'ACTIVE'}]
        self.g.responses[('container_engine',R,'get_node_pool')]=({'id':'pool','compartment_id':P,
            'lifecycle_state':'ACTIVE','nodes':[{'id':'i','node_pool_id':'pool','lifecycle_state':'ACTIVE'}]}, {})
        self.assertEqual(self.compute.inspect(self.g,next(n for n in nodes if n.key=='i'),{P,C}).status,'unresolved')

    def test_live_cascade_includes_scoped_vnic_private_and_ephemeral_public_ips(self):
        self.g.add_row(resource('i','Instance',state='RUNNING'),'list_instances')
        self.g.add_row(resource('a','VnicAttachment',state='ATTACHED',metadata={'instance_id':'i','vnic_id':'nic'}),'list_vnic_attachments')
        self.g.add(resource('nic','Vnic',C,'AVAILABLE',{'subnet_id':'subnet','nsg_ids':[],'private_ip':'10.0.0.2','public_ip':'203.0.113.2'}))
        self.g.add_row(resource('ip','PrivateIp',C,'',{'vnic_id':'nic','subnet_id':'subnet','lifetime':'EPHEMERAL','ip_state':'ASSIGNED','ip_address':'10.0.0.2','is_primary':True}),'list_private_ips')
        self.g.add_row(resource('pub','PublicIp',C,'ASSIGNED',{'private_ip_id':'ip','assigned_entity_id':'ip',
            'ip_address':'203.0.113.2','assigned_entity_type':'PRIVATE_IP','lifetime':'EPHEMERAL','scope':'AVAILABILITY_DOMAIN','availability_domain':'AD-one'}),'list_public_ips')
        nodes,edges,_=self.compute.discover(self.g,P,R)
        by_id={n.key:n for n in nodes}
        self.assertEqual(set(by_id),{'i','a','nic','ip','pub'})
        self.assertEqual(set(by_id['i'].metadata['cascade_members']),{'a','nic','ip','pub'})
        self.assertFalse(by_id['i'].blockers)
        for key in ('a','nic','ip','pub'):
            self.assertEqual(by_id[key].metadata['cascade_owner'],'i')
            self.assertTrue(by_id[key].metadata['cascade_verified'])
        self.assertIn(('i','subnet'),{(e.before,e.after) for e in edges})
        self.assertEqual(self.compute.inspect(self.g,by_id['i'],{P,C}).status,'present')
        self.g.resources['pub']=replace(self.g.resources['pub'],compartment_id=X)
        self.assertEqual(self.compute.inspect(self.g,by_id['i'],{P,C}).status,'unresolved')

    def test_new_cascade_member_requires_plan_refresh(self):
        self.g.add_row(resource('i','Instance',state='RUNNING'),'list_instances')
        nodes,_,_=self.compute.discover(self.g,P,R)
        n=nodes[0]
        self.g.add_row(resource('a','VnicAttachment',state='ATTACHED',metadata={'instance_id':'i','vnic_id':'nic'}),'list_vnic_attachments')
        self.g.add(resource('nic','Vnic',state='AVAILABLE',metadata={'subnet_id':'s'}))
        self.assertEqual(self.compute.inspect(self.g,n,{P,C}).status,'unresolved')

    def test_cascade_boot_attachment_live_running_owner_is_safe_to_confirm(self):
        self.g.add_row(resource('i','Instance',state='RUNNING'),'list_instances')
        self.g.add_row(resource('a','BootVolumeAttachment',state='ATTACHED',metadata={'instance_id':'i','boot_volume_id':'boot','availability_domain':'AD-one'}),'list_boot_volume_attachments')
        self.g.add(resource('boot','BootVolume'))
        nodes,_,_=self.compute.discover(self.g,P,R)
        n=next(n for n in nodes if n.key=='a')
        self.assertEqual(n.metadata['cascade_owner'],'i')
        self.assertEqual(self.compute.inspect(self.g,n,{P,C}).status,'present')
        with self.assertRaises(CleanupError):
            self.compute.submit(self.g,n,self.compute.inspect(self.g,n,{P,C}),'attempt')

    def test_volume_attachment_move_between_list_and_get_blocks_deletion(self):
        n=resource('v','Volume')
        self.g.add(n)
        self.g.add_row(resource('a','VolumeAttachment',C,'ATTACHED',{'instance_id':'i','volume_id':'v','attachment_type':'iscsi'}),'list_volume_attachments')
        self.g.resources['a']=replace(self.g.resources['a'],compartment_id=X)
        self.g.add(resource('i','Instance',C,'RUNNING'))
        nodes,_,_=self.volumes.discover(self.g,P,R)
        # Add the volume to discovery too: the planner must not return a falsely safe action.
        self.g.add_row(n,'list_volumes')
        nodes,_,_=self.volumes.discover(self.g,P,R)
        self.assertTrue(nodes[0].blockers)

    def test_reserved_public_ip_is_retained_and_external_ephemeral_blocks(self):
        self.g.add_row(resource('i','Instance',state='RUNNING'),'list_instances')
        self.g.add_row(resource('a','VnicAttachment',state='ATTACHED',metadata={'instance_id':'i','vnic_id':'nic'}),'list_vnic_attachments')
        self.g.add(resource('nic','Vnic',state='AVAILABLE',metadata={'subnet_id':'subnet','private_ip':'10.0.0.2','public_ip':'203.0.113.2'}))
        self.g.add_row(resource('ip','PrivateIp',P,'',{'vnic_id':'nic','subnet_id':'subnet','lifetime':'EPHEMERAL','ip_state':'ASSIGNED','ip_address':'10.0.0.2','is_primary':True}),'list_private_ips')
        self.g.add_row(resource('pub','PublicIp',X,'ASSIGNED',{'private_ip_id':'ip','assigned_entity_id':'ip',
            'ip_address':'203.0.113.2','assigned_entity_type':'PRIVATE_IP','lifetime':'RESERVED','scope':'REGION'}),'list_public_ips')
        nodes,_,_=self.compute.discover(self.g,P,R)
        self.assertNotIn('pub',{n.key for n in nodes})
        instance=next(n for n in nodes if n.key=='i')
        self.assertFalse(instance.blockers)
        self.assertEqual(instance.metadata['retained_public_ips'][0]['id'],'pub')
        ephemeral=replace(self.g.resources['pub'],metadata=dict(self.g.resources['pub'].metadata,
            lifetime='EPHEMERAL',scope='AVAILABILITY_DOMAIN',availability_domain='AD-one'))
        self.g.rows['list_public_ips']=[]
        self.g.add_row(ephemeral,'list_public_ips')
        nodes,_,_=self.compute.discover(self.g,P,R)
        self.assertTrue(next(n for n in nodes if n.key=='i').blockers)

    def test_submission_rechecks_owner_and_reference_after_observation(self):
        n=resource('v','Volume')
        self.g.add(n)
        observation=self.volumes.inspect(self.g,n,{P,C})
        self.g.resources['v']=replace(n,compartment_id=X)
        with self.assertRaises(CleanupError):
            self.volumes.submit(self.g,n,observation,'attempt')
        self.assertFalse(any(event[0]=='write' for event in self.g.events))

    def test_submission_requires_validated_scope(self):
        n=resource('p','Policy',state='ACTIVE')
        self.g.add(n)
        observation=self.policies.inspect(self.g,n,{P})
        self.g.cleanup_scope=set()
        with self.assertRaises(CleanupError):
            self.policies.submit(self.g,n,observation,'attempt')

    def test_failed_private_ip_page_blocks_full_instance_cascade(self):
        self.g.add_row(resource('i','Instance',state='RUNNING'),'list_instances')
        self.g.add_row(resource('a','VnicAttachment',state='ATTACHED',metadata={'instance_id':'i','vnic_id':'nic'}),'list_vnic_attachments')
        self.g.add(resource('nic','Vnic',state='AVAILABLE',metadata={'subnet_id':'subnet'}))
        self.g.rows['list_private_ips']=CleanupError('last page denied')
        nodes,_,_=self.compute.discover(self.g,P,R)
        self.assertTrue(next(n for n in nodes if n.key=='i').blockers)
        self.assertFalse(any(n.metadata.get('cascade_verified') for n in nodes))

    def test_same_cascade_ids_with_changed_external_volume_requires_refresh(self):
        self.g.add_row(resource('i','Instance',state='RUNNING'),'list_instances')
        self.g.add_row(resource('a','VolumeAttachment',state='ATTACHED',metadata={'instance_id':'i','volume_id':'external-volume','attachment_type':'iscsi'}),'list_volume_attachments')
        self.g.add(resource('external-volume','Volume',X))
        nodes,_,_=self.compute.discover(self.g,P,R)
        n=next(n for n in nodes if n.key=='i')
        self.g.resources['a']=replace(self.g.resources['a'],metadata=dict(self.g.resources['a'].metadata,volume_id='other-volume'))
        self.g.rows['list_volume_attachments'][0]['volume_id']='other-volume'
        self.g.add(resource('other-volume','Volume',X))
        self.assertEqual(self.compute.inspect(self.g,n,{P,C}).status,'unresolved')

    def test_reserved_private_ip_or_unlisted_ipv6_coverage_blocks_instance(self):
        self.g.add_row(resource('i','Instance',state='RUNNING'),'list_instances')
        self.g.add_row(resource('a','VnicAttachment',state='ATTACHED',metadata={'instance_id':'i','vnic_id':'nic'}),'list_vnic_attachments')
        self.g.add(resource('nic','Vnic',state='AVAILABLE',metadata={'subnet_id':'subnet','ipv6_addresses':[]}))
        self.g.add_row(resource('ip','PrivateIp',P,'',{'vnic_id':'nic','subnet_id':'subnet','lifetime':'RESERVED','ip_state':'ASSIGNED'}),'list_private_ips')
        nodes,_,_=self.compute.discover(self.g,P,R)
        self.assertTrue(next(n for n in nodes if n.key=='i').blockers)
        self.g.rows['list_private_ips']=[]
        self.g.rows['list_ipv6s']=[{'id':'ipv6','vnic_id':'nic','compartment_id':P,'lifecycle_state':'AVAILABLE','lifetime':'EPHEMERAL'}]
        nodes,_,_=self.compute.discover(self.g,P,R)
        self.assertTrue(next(n for n in nodes if n.key=='i').blockers)

    def test_deleted_producer_summary_does_not_prove_member_cleanup(self):
        self.g.add_row(resource('i','Instance',state='RUNNING'),'list_instances')
        self.g.rows['list_node_pools']=[{'id':'pool','compartment_id':P,'lifecycle_state':'DELETED'}]
        self.g.responses[('container_engine',R,'get_node_pool')]=({'id':'pool','compartment_id':P,
            'lifecycle_state':'DELETED','nodes':[{'id':'i','node_pool_id':'pool','lifecycle_state':'DELETED'}]}, {})
        nodes,_,_=self.compute.discover(self.g,P,R)
        self.assertTrue(next(n for n in nodes if n.key=='i').blockers)

    def addressed_instance(self):
        self.g.add_row(resource('i','Instance',state='RUNNING'),'list_instances')
        self.g.add_row(resource('a','VnicAttachment',state='ATTACHED',metadata={'instance_id':'i','vnic_id':'nic'}),'list_vnic_attachments')
        self.g.add(resource('nic','Vnic',state='AVAILABLE',metadata=oci.util.to_dict(oci.core.models.Vnic(
            subnet_id='subnet',private_ip='10.0.0.2',public_ip='203.0.113.2'))))
        self.g.add_row(resource('ip','PrivateIp',P,'',oci.util.to_dict(oci.core.models.PrivateIp(
            vnic_id='nic',subnet_id='subnet',lifetime='EPHEMERAL',ip_state='ASSIGNED',
            ip_address='10.0.0.2',is_primary=True))),'list_private_ips')
        self.g.add_row(resource('pub','PublicIp',P,'ASSIGNED',oci.util.to_dict(oci.core.models.PublicIp(
            private_ip_id='ip',assigned_entity_id='ip',assigned_entity_type='PRIVATE_IP',ip_address='203.0.113.2',
            lifetime='EPHEMERAL',scope='AVAILABILITY_DOMAIN',availability_domain='AD-one'))),'list_public_ips')

    def test_vnic_addresses_require_reciprocal_private_and_public_inventory(self):
        self.addressed_instance()
        self.g.rows['list_private_ips']=[]
        self.g.rows['list_public_ips']=[]
        nodes,_,_=self.compute.discover(self.g,P,R)
        self.assertTrue(next(n for n in nodes if n.key=='i').blockers)
        self.assertFalse(any(n.metadata.get('cascade_verified') for n in nodes))

    def test_primary_private_ip_address_or_primary_flag_mismatch_blocks(self):
        for change in ({'ip_address':'10.0.0.3'},{'is_primary':False}):
            with self.subTest(change=change):
                self.g=CoreGateway()
                self.addressed_instance()
                self.g.resources['ip']=replace(self.g.resources['ip'],metadata=dict(self.g.resources['ip'].metadata,**change))
                self.g.rows['list_private_ips'][0].update(change)
                nodes,_,_=self.compute.discover(self.g,P,R)
                self.assertTrue(next(n for n in nodes if n.key=='i').blockers)

    def test_primary_public_ip_requires_exact_address_and_matching_association_ids(self):
        for change in ({'assigned_entity_id':'different-private-ip'},{'ip_address':'203.0.113.3'}):
            with self.subTest(change=change):
                self.g=CoreGateway()
                self.addressed_instance()
                self.g.resources['pub']=replace(self.g.resources['pub'],metadata=dict(self.g.resources['pub'].metadata,**change))
                self.g.rows['list_public_ips'][0].update(change)
                nodes,_,_=self.compute.discover(self.g,P,R)
                self.assertTrue(next(n for n in nodes if n.key=='i').blockers)
        self.g=CoreGateway()
        self.addressed_instance()
        self.g.rows['list_public_ips']=[]
        self.assertTrue(next(n for n in self.compute.discover(self.g,P,R)[0] if n.key=='i').blockers)

    def test_address_and_primary_membership_drift_blocks_submission(self):
        self.addressed_instance()
        nodes,_,_=self.compute.discover(self.g,P,R)
        n=next(n for n in nodes if n.key=='i')
        self.assertFalse(n.blockers)
        observation=self.compute.inspect(self.g,n,{P,C})
        self.assertEqual(observation.status,'present')
        # Change every live endpoint consistently, keeping the exact same child IDs.
        self.g.resources['nic']=replace(self.g.resources['nic'],metadata=dict(self.g.resources['nic'].metadata,
            private_ip='10.0.0.3',public_ip='203.0.113.3'))
        self.g.resources['ip']=replace(self.g.resources['ip'],metadata=dict(self.g.resources['ip'].metadata,ip_address='10.0.0.3'))
        self.g.rows['list_private_ips'][0]['ip_address']='10.0.0.3'
        self.g.resources['pub']=replace(self.g.resources['pub'],metadata=dict(self.g.resources['pub'].metadata,ip_address='203.0.113.3'))
        self.g.rows['list_public_ips'][0]['ip_address']='203.0.113.3'
        self.assertEqual(self.compute.inspect(self.g,n,{P,C}).status,'unresolved')
        with self.assertRaises(CleanupError):
            self.compute.submit(self.g,n,observation,'attempt')
        self.assertFalse(any(event[0]=='write' for event in self.g.events))

    def test_terminal_states_are_type_specific(self):
        for kind,state,handler,want in [('Volume','TERMINATED',self.volumes,'deleted'),
            ('BootVolumeBackup','FAULTY',self.volumes,'unresolved'),('VolumeAttachment','DETACHED',self.compute,'deleted'),
            ('Instance','TERMINATING',self.compute,'pending'),('Instance','TERMINATED',self.compute,'deleted')]:
            n=resource('n',kind,state=state)
            self.g.add(n)
            self.assertEqual(handler.inspect(self.g,n,{P,C}).status,want)


class CoreIntegrationTests(unittest.TestCase):
    def test_scope_snapshot_keeps_full_tenancy_links_separate(self):
        from test_gateway import Scope, P as parent, C as child, U as external
        gateway=Scope()
        discover_scope(gateway,parent)
        self.assertEqual(getattr(gateway,'cleanup_scope',None),{parent,child})
        self.assertIn(external,gateway.compartment_links)

    def test_policy_late_ordering_includes_unknown_resources_and_strict_descendant_compartments(self):
        from test_discovery import Inventory, P as parent, C as child, T as tenancy
        sibling='ocid1.compartment.oc1..sibling'
        gateway=Inventory()
        gateway.compartment_links[sibling]=parent
        gateway.search=[{'identifier':'unknown','resource_type':'Mystery','compartment_id':sibling}]
        def items(service,region,operation,params,endpoint=None):
            if operation=='search_resources':
                return [row for row in gateway.search if row['compartment_id'] in params['search_details'].query]
            if operation=='list_policies':
                owner=params['compartment_id']
                return [{'id':'policy-'+owner,'compartment_id':owner,'lifecycle_state':'ACTIVE'}]
            return Inventory.items(gateway,service,region,operation,params,endpoint)
        gateway.items=items
        gateway.read_original=gateway.read
        def read(service,region,operation,params,endpoint=None):
            if operation=='get_policy':
                key=params['policy_id']
                return {'id':key,'compartment_id':key[len('policy-'):],'lifecycle_state':'ACTIVE'},{'etag':'etag'}
            return gateway.read_original(service,region,operation,params,endpoint)
        gateway.read=read
        plan=discover(gateway,parent,Registry({'policies':IAMPolicies()}))
        pairs={(edge.before,edge.after) for edge in plan.edges}
        self.assertIn(('unknown','policy-'+parent),pairs)
        self.assertIn((child,'policy-'+parent),pairs)
        self.assertIn((sibling,'policy-'+parent),pairs)
        self.assertNotIn((sibling,'policy-'+child),pairs)
        self.assertNotIn((child,'policy-'+sibling),pairs)
        self.assertFalse(any('Cyclic' in reason for node in plan.nodes.values() for reason in node.blockers))

    def test_encryption_key_outbound_reference_is_retained_or_ordered_when_inscope(self):
        parent='ocid1.compartment.oc1..parent'
        child='ocid1.compartment.oc1..child'
        tenancy='ocid1.tenancy.oc1..tenancy'
        gateway=CoreGateway()
        gateway.tenancy_id=tenancy
        gateway.compartment_links={parent:tenancy,child:parent}
        gateway.cleanup_scope={parent,child}
        gateway.add_row(resource('v','Volume',parent,metadata={'kms_key_id':'key'}),'list_volumes')
        search=[]
        def items(service,region,operation,params,endpoint=None):
            if operation in ('list_region_subscriptions','list_compartments'):
                return Simulator.items(gateway,service,region,operation,params,endpoint)
            if operation=='list_bulk_action_resource_types':
                return []
            if operation=='search_resources':
                return [row for row in search if row['compartment_id'] in params['search_details'].query]
            return CoreGateway.items(gateway,service,region,operation,params,endpoint)
        gateway.items=items
        registry=Registry({'blockstorage':BlockBootVolumes()})
        plan=discover(gateway,parent,registry)
        self.assertFalse(plan.nodes['v'].blockers)
        self.assertEqual(plan.nodes['v'].metadata['kms_key_id'],'key')
        self.assertFalse(any(edge.after=='key' for edge in plan.edges))
        search.append({'identifier':'key','resource_type':'Key','compartment_id':parent})
        plan=discover(gateway,parent,registry)
        self.assertIn(('v','key'),{(edge.before,edge.after) for edge in plan.edges})

    def test_sdk_core_read_only_bindings_and_safe_termination_contract(self):
        cases=[
            ('compute_management',oci.core.ComputeManagementClient,'list_instance_pools',{'compartment_id':'c'}),
            ('compute_management',oci.core.ComputeManagementClient,'list_instance_pool_instances',{'compartment_id':'c','instance_pool_id':'pool'}),
            ('container_engine',oci.container_engine.ContainerEngineClient,'list_clusters',{'compartment_id':'c'}),
            ('container_engine',oci.container_engine.ContainerEngineClient,'list_node_pools',{'compartment_id':'c'}),
            ('container_engine',oci.container_engine.ContainerEngineClient,'get_node_pool',{'node_pool_id':'pool'}),
            ('network',oci.core.VirtualNetworkClient,'list_ipv6s',{'vnic_id':'nic'}),
            ('network',oci.core.VirtualNetworkClient,'get_private_ip',{'private_ip_id':'ip'}),
            ('network',oci.core.VirtualNetworkClient,'get_public_ip',{'public_ip_id':'ip'}),
            ('network',oci.core.VirtualNetworkClient,'list_public_ips',{'compartment_id':'c','scope':'AVAILABILITY_DOMAIN','lifetime':'EPHEMERAL','availability_domain':'AD-one'}),
            ('compute',oci.core.ComputeClient,'terminate_instance',{'instance_id':'i','if_match':'etag','preserve_boot_volume':True,'preserve_data_volumes_created_at_launch':True}),
        ]
        config={'tenancy':'ocid1.tenancy.oc1..t','region':'eu-frankfurt-1'}
        for service,client_class,operation,params in cases:
            with self.subTest(operation=operation):
                signer=Mock(spec=oci.auth.signers.InstancePrincipalsSecurityTokenSigner)
                client=client_class(config,signer=signer)
                calls=[]
                def call_api(*args,**kwargs):
                    calls.append((args,kwargs))
                    return SimpleNamespace(data=[],headers={})
                client.base_client.call_api=call_api
                gateway=Gateway(config)
                gateway._clients[(service,'eu-frankfurt-1',None)]=client
                if operation=='terminate_instance':
                    gateway.write(service,'eu-frankfurt-1',operation,params)
                    query=calls[0][1]['query_params']
                    self.assertEqual(query['preserveBootVolume'],True)
                    self.assertEqual(query['preserveDataVolumesCreatedAtLaunch'],True)
                else:
                    gateway.read(service,'eu-frankfurt-1',operation,params)
                self.assertEqual(len(calls),1)
                with self.assertRaises(CleanupError):
                    gateway.write(service,'eu-frankfurt-1',operation,params) if operation!='terminate_instance' else gateway.read(service,'eu-frankfurt-1',operation,params)


if __name__ == '__main__':
    unittest.main()
