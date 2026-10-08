"""Bulk helpers exercised against durable journals and actual SDK models."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
import oci
from compartment_cleanup.model import Node, Plan, State, Edge, CleanupError
from compartment_cleanup.handlers.base import Registry
from compartment_cleanup.handlers.core import BlockBootVolumes, ComputeInstances
from compartment_cleanup.handlers.network import Networks
from compartment_cleanup.handlers.storage import Storage
from compartment_cleanup.store import Workspace
from compartment_cleanup.gateway import _normalize, GatewayError
from test_core import CoreGateway, resource, P, C, X, R
from simulator import StorageSimulator
from test_storage import obj
try:
    from compartment_cleanup.executor import bulk_groups, submit_bulk, inspect_bulk
except ImportError:
    bulk_groups = submit_bulk = inspect_bulk = None

NOW=datetime(2026,10,8,tzinfo=timezone.utc)


def plan_for(nodes, edges=(), catalog=None, parent=P, child=C):
    retained=Node(parent,'Compartment','home','tenancy','','ACTIVE','','retain',{})
    return Plan(1,'tenancy',parent,'home',NOW.isoformat(),{parent:'tenancy',child:parent},
                {n.key:n for n in [retained,*nodes]},list(edges),[],{},catalog or {'VolumeBackup':()})


class BulkGateway(CoreGateway):
    def __init__(self):
        super().__init__();self.home_region='home';self.catalog=[{'name':'VolumeBackup','metadata_keys':[]}]
        self.header={'opc-workrequest-id':'wr'};self.before_write=None
    def items(self,service,region,operation,params,endpoint=None):
        if operation=='list_bulk_action_resource_types':
            self._event('items',service,region,operation,params,endpoint);return deepcopy(self.catalog)
        return super().items(service,region,operation,params,endpoint)
    def write(self,service,region,operation,params,endpoint=None):
        if operation=='bulk_delete_resources':
            if self.before_write:self.before_write(params)
            self._event('write',service,region,operation,params,endpoint)
            if isinstance(self.header,Exception):raise self.header
            return None,deepcopy(self.header)
        return super().write(service,region,operation,params,endpoint)


class BulkTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(bulk_groups,'Task8 bulk helpers required')
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.ws=Workspace(Path(self.tmp.name));self.g=BulkGateway();self.registry=Registry({'blockstorage':BlockBootVolumes(),'compute':ComputeInstances(),'network':Networks()})
        self.nodes=[self.registry.classify(resource('a','VolumeBackup',state='AVAILABLE')),self.registry.classify(resource('b','VolumeBackup',state='AVAILABLE'))]
        for n in self.nodes:self.g.add_row(n,'list_volume_backups')
        self.plan=plan_for(self.nodes);self.state=State(1,'tenancy',P,{})
    def submit(self,nodes=None,token='token'):
        with self.ws.locked():
            return submit_bulk(self.g,self.plan,nodes or self.nodes,token,registry=self.registry,workspace=self.ws,state=self.state,now=NOW)
    def inspect(self,**kw):
        with self.ws.locked():
            return inspect_bulk(self.g,self.plan,'wr',registry=self.registry,workspace=self.ws,state=self.state,**kw)
    def wr(self,status='SUCCEEDED',resources=None,operation=None):
        model=oci.identity.models.WorkRequest(id='wr',compartment_id=P,status=status,operation_type=operation or 'UNKNOWN_ENUM_VALUE',resources=resources or [oci.identity.models.WorkRequestResource(identifier=n.key,entity_type='VolumeBackup',action_type='DELETED') for n in self.nodes])
        self.g.work_requests['wr']=_normalize(model)
    def writes(self):return [e for e in self.g.events if e[0]=='write']
    def test_groups_recompute_depth_and_split_compartment_region_phase_and_twenty(self):
        nodes=[self.registry.classify(resource(str(i),'VolumeBackup',state='AVAILABLE')) for i in range(23)]
        nodes += [replace(nodes[0],key='other',compartment_id=C),replace(nodes[0],key='region',region='other')]
        p=plan_for(nodes,[Edge('0','1','dependency')]);p.depths={n.key:99 for n in nodes}
        groups=bulk_groups(p,nodes,self.registry)
        self.assertEqual(sorted(len(g) for g in groups),[1,1,1,2,20])
        self.assertFalse(any({'0','1'} <= {n.key for n in g} for g in groups))
    def test_group_excludes_metadata_flags_scheduled_cascade_unknown_and_case_aliases(self):
        bad=[replace(self.nodes[0],key='scheduled',action='schedule'),replace(self.nodes[0],key='cascade',metadata={'cascade_owner':'x'}),resource('i','Instance',state='RUNNING'),resource('unknown','Other',state='AVAILABLE')]
        p=plan_for(self.nodes+bad,catalog={'volumebackup':()})
        self.assertEqual(bulk_groups(p,self.nodes+bad,self.registry),[])
        p.bulk_types={'VolumeBackup':('unknownRequiredKey',)}
        self.assertEqual(bulk_groups(p,self.nodes,self.registry),[])
    def test_blocked_predecessor_excludes_downstream_and_untrusted_ready_node(self):
        a=replace(self.nodes[0],blockers=('blocked',));p=plan_for([a,self.nodes[1]],[Edge('a','b','dep')])
        self.assertEqual(bulk_groups(p,[a,self.nodes[1]],self.registry),[])
        with self.assertRaises(CleanupError):bulk_groups(self.plan,[replace(self.nodes[0],compartment_id=X)],self.registry)
    def test_actual_sdk_payload_home_routing_and_durable_intent_before_write(self):
        self.plan.nodes['a']=replace(self.nodes[0],metadata={'bulk_resource_type':'evil','bulk_metadata':{'inject':'value'}})
        self.nodes[0]=self.plan.nodes['a']
        def assert_journal(params):
            loaded=self.ws._read('state.json');attempt=loaded['records']['a']['attempts'][0]
            self.assertEqual(attempt['opc_retry_token'],'token');self.assertEqual(attempt['started_at'],NOW.isoformat())
            self.assertEqual(attempt['resources'],[{'identifier':'a','entity_type':'VolumeBackup','metadata':{}},{'identifier':'b','entity_type':'VolumeBackup','metadata':{}}])
        self.g.before_write=assert_journal
        result=self.submit();self.assertEqual(result.request_id,'wr')
        write=self.writes()[0];self.assertEqual(write[2],'home')
        details=write[4]['bulk_delete_resources_details']
        client=object.__new__(oci.base_client.BaseClient);client.complex_type_mappings=oci.identity.models.__dict__
        serialized=client.sanitize_for_serialization(details)
        self.assertEqual(serialized,{'resources':[{'identifier':'a','entityType':'VolumeBackup','metadata':{}},{'identifier':'b','entityType':'VolumeBackup','metadata':{}}]})
    def test_no_journal_or_failed_journal_never_mutates(self):
        with self.assertRaises(CleanupError):submit_bulk(self.g,self.plan,self.nodes,'token',registry=self.registry)
        with self.assertRaises(CleanupError):submit_bulk(self.g,self.plan,self.nodes,'token',registry=self.registry,workspace=self.ws,state=self.state,now=NOW)
        self.assertFalse(self.writes())
    def test_fresh_catalog_metadata_scope_and_dependencies_fail_before_write(self):
        for catalog in ([{'name':'volumebackup','metadata_keys':[]}],[{'name':'VolumeBackup','metadata_keys':['unknown']}],[]):
            self.g.catalog=catalog
            with self.assertRaises(CleanupError):self.submit()
        self.g.catalog=[{'name':'VolumeBackup','metadata_keys':[]}];self.g.resources['a']=replace(self.nodes[0],compartment_id=X)
        with self.assertRaises(CleanupError):self.submit()
        self.assertFalse(self.writes())
    def test_header_spellings_are_case_insensitive_and_conflicts_or_trace_only_unresolved(self):
        for headers,expected in [({'OPC-WORK-REQUEST-ID':'wr'},'wr'),({'opc-workrequest-id':'wr','OPC-WORK-REQUEST-ID':'other'},None),({'opc-request-id':'trace'},None)]:
            self.setUp();self.g.header=headers;result=self.submit();self.assertEqual(result.request_id,expected)
            if expected is None:self.assertEqual(result.status,'unresolved')
    def test_lost_response_is_journaled_and_cannot_blindly_replay_or_change_token(self):
        self.g.header=GatewayError('identity','bulk_delete_resources')
        self.assertEqual(self.submit().status,'unresolved')
        for token in ('token','new'):
            with self.assertRaises(CleanupError):self.submit(token=token)
        self.assertEqual(len(self.writes()),1)
    def test_retry_token_cannot_be_reused_for_a_different_group(self):
        self.submit(nodes=[self.nodes[0]])
        with self.assertRaises(CleanupError):self.submit(nodes=[self.nodes[1]])
        self.assertEqual(len(self.writes()),1)

    def test_failed_resource_retry_keeps_old_partial_history_and_never_retries_deleted(self):
        self.submit();self.wr('FAILED',[oci.identity.models.WorkRequestResource(identifier='a',entity_type='VolumeBackup',action_type='DELETED'),oci.identity.models.WorkRequestResource(identifier='b',entity_type='VolumeBackup',action_type='FAILED')])
        self.g.resources.pop('a');self.g.rows['list_volume_backups']=[r for r in self.g.rows['list_volume_backups'] if r['id']!='a']
        self.inspect()
        with self.assertRaises(CleanupError):self.submit(nodes=[self.nodes[0]],token='new')
        self.g.header={'opc-work-request-id':'wr2'}
        self.submit(nodes=[self.nodes[1]],token='new')
        self.assertEqual(len(self.state.records['a']['attempts']),1)
        self.assertEqual([a['request_id'] for a in self.state.records['b']['attempts']],['wr','wr2'])
        self.assertEqual([r.identifier for r in self.writes()[-1][4]['bulk_delete_resources_details'].resources],['b'])

    def test_partial_failed_preserves_deleted_item_and_requires_live_absence(self):
        self.submit();self.wr('FAILED',[oci.identity.models.WorkRequestResource(identifier='a',entity_type='VolumeBackup',action_type='DELETED'),oci.identity.models.WorkRequestResource(identifier='b',entity_type='VolumeBackup',action_type='FAILED')])
        self.g.resources.pop('a');self.g.rows['list_volume_backups']=[r for r in self.g.rows['list_volume_backups'] if r['id']!='a']
        result=self.inspect();self.assertEqual(result['resources'],{'a':'deleted','b':'failed'});self.assertEqual(result['status'],'failed')
        self.assertEqual(self.state.records['a']['attempts'][0]['resource_evidence']['a']['action_type'],'DELETED')
    def test_success_without_exact_deleted_or_live_active_never_confirms(self):
        self.submit();self.wr();self.assertEqual(self.inspect()['resources']['a'],'unresolved')
        for rows in ([oci.identity.models.WorkRequestResource(identifier='a',entity_type='VolumeBackup',action_type='RELATED')],[],[oci.identity.models.WorkRequestResource(identifier='a',entity_type='volumebackup',action_type='DELETED')]):
            self.wr(resources=rows);self.g.work_requests['wr']['resources']=_normalize(rows)
            self.assertNotEqual(self.inspect()['resources'].get('a'),'deleted')
    def test_work_request_scope_operation_duplicate_unexpected_and_malformed_fail_closed(self):
        self.submit();self.wr()
        for field,value in [('id','other'),('compartment_id',X),('operation_type','DELETE_COMPARTMENT'),('errors',{}),('logs','bad')]:
            self.wr();self.g.work_requests['wr'][field]=value;self.assertEqual(self.inspect()['status'],'unresolved')
        for extra in [oci.identity.models.WorkRequestResource(identifier='a',entity_type='VolumeBackup',action_type='DELETED'),oci.identity.models.WorkRequestResource(identifier='foreign',entity_type='VolumeBackup',action_type='DELETED')]:
            self.wr();self.g.work_requests['wr']['resources'].append(_normalize(extra));self.assertEqual(self.inspect()['status'],'unresolved')
    def test_pending_wait_is_bounded_and_persisted_with_optional_null_arrays(self):
        self.submit();self.wr('IN_PROGRESS');clock=[0];waits=[]
        def sleep(seconds):waits.append(seconds);clock[0]+=seconds
        result=self.inspect(wait_seconds=3,clock=lambda:clock[0],sleep=sleep)
        self.assertEqual(result['status'],'pending');self.assertLessEqual(sum(waits),3)
        self.assertEqual(self.state.records['a']['attempts'][0]['work_request']['status'],'IN_PROGRESS')
    def test_denied_complete_inventory_cannot_corroborate_positive_deleted(self):
        self.submit();self.wr();self.g.resources.clear();self.g.rows['list_volume_backups']=GatewayError('blockstorage','list_volume_backups',403)
        self.assertEqual(self.inspect()['resources']['a'],'unresolved')
    def test_storage_batch_journals_exact_etags_and_persists_positive_results(self):
        g=StorageSimulator();g.home_region='home';h=Storage();g.inventory['list_objects']=[obj('a'),obj('b')]
        all_nodes,edges,_=h.discover(g,'child',R);nodes=[n for n in all_nodes if n.resource_type=='ObjectStorageObject']
        registry=Registry({'storage':h});p=plan_for(all_nodes,parent='parent',child='child');state=State(1,'tenancy','parent',{})
        with self.ws.locked():result=submit_bulk(g,p,nodes,'storage-token',registry=registry,workspace=self.ws,state=state,now=NOW)
        self.assertEqual(result.status,'pending');self.assertIsNone(result.request_id)
        for n in nodes:
            attempt=state.records[n.key]['attempts'][0]
            self.assertEqual(attempt['operation'],'batch_delete_objects');self.assertEqual(attempt['payload']['objects'][0],{'object_name':'a','if_match':'etag-a'})
            self.assertIsNotNone(attempt['resource_evidence'][n.key])
        self.assertEqual([e[3] for e in g.events if e[0]=='write'],['batch_delete_objects'])

    def test_failed_iam_persistence_has_zero_mutations(self):
        def fail_save(state):raise CleanupError('disk failure')
        self.ws.save_state=fail_save
        with self.assertRaises(CleanupError):self.submit()
        self.assertEqual(self.writes(),[])

    def test_optional_null_wr_arrays_allowed_but_resources_null_unresolved(self):
        self.submit();self.wr()
        self.assertIsNone(self.g.work_requests['wr']['errors'])
        self.assertIsNone(self.g.work_requests['wr']['logs'])
        self.g.resources.clear();self.g.rows['list_volume_backups']=[]
        self.assertEqual(self.inspect()['status'],'deleted')
        self.g.work_requests['wr']['resources']=None
        self.assertEqual(self.inspect()['status'],'unresolved')

    def test_later_missing_entries_do_not_erase_historical_positive_fact(self):
        self.submit();self.wr();self.inspect()
        self.g.work_requests['wr']['resources']=[]
        self.assertEqual(self.inspect()['resources']['a'],'unresolved')
        self.assertEqual(self.state.records['a']['attempts'][0]['resource_evidence']['a']['action_type'],'DELETED')

    def test_exact_network_deleted_plus_full_inventory_and_new_consumer(self):
        n=self.registry.classify(resource('nat','NatGateway',state='AVAILABLE'))
        self.g.add_row(n,'list_nat_gateways');self.g.catalog=[{'name':'NatGateway','metadata_keys':[]}]
        self.nodes=[n];self.plan=plan_for([n],catalog={'NatGateway':()})
        self.submit();self.wr(resources=[oci.identity.models.WorkRequestResource(identifier='nat',entity_type='NatGateway',action_type='DELETED')])
        self.g.resources.pop('nat');self.g.rows['list_nat_gateways']=[]
        self.assertEqual(self.inspect()['resources']['nat'],'deleted')
        self.g.add_row(resource('route','RouteTable',X,metadata={'route_rules':[{'network_entity_id':'nat'}]}),'list_route_tables')
        self.assertEqual(self.inspect()['resources']['nat'],'unresolved')

    def test_live_get_dependency_drift_wins_even_when_lists_hide_active_identity(self):
        self.submit();self.wr()
        self.g.resources['a']=replace(self.nodes[0],metadata={'kms_key_id':'new'})
        self.g.rows['list_volume_backups']=[]
        self.assertEqual(self.inspect()['resources']['a'],'unresolved')

    def test_live_network_get_drift_wins_even_when_inventory_omits_it(self):
        n=self.registry.classify(resource('nat','NatGateway',state='AVAILABLE'))
        self.g.add_row(n,'list_nat_gateways');self.g.catalog=[{'name':'NatGateway','metadata_keys':[]}]
        self.nodes=[n];self.plan=plan_for([n],catalog={'NatGateway':()})
        self.submit();self.wr(resources=[oci.identity.models.WorkRequestResource(identifier='nat',entity_type='NatGateway',action_type='DELETED')])
        self.g.resources['nat']=replace(n,metadata={'vcn_id':'changed'})
        self.g.rows['list_nat_gateways']=[]
        self.assertEqual(self.inspect()['resources']['nat'],'unresolved')

    def test_untrusted_mutated_state_cannot_supply_work_request(self):
        self.submit();self.wr();self.state.records['a']['attempts'][0]['compartment_id']=X
        with self.assertRaises(CleanupError):self.inspect()


class StorageBulkTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.ws=Workspace(Path(self.tmp.name))
        self.g=StorageSimulator();self.g.home_region='home';self.h=Storage()
        self.g.inventory['list_objects']=[obj('a'),obj('b')]
        all_nodes,_,_=self.h.discover(self.g,'child',R)
        self.nodes=[n for n in all_nodes if n.resource_type=='ObjectStorageObject']
        self.p=plan_for(all_nodes,parent='parent',child='child');self.registry=Registry({'storage':self.h});self.state=State(1,'tenancy','parent',{})
    def submit(self):
        with self.ws.locked():return submit_bulk(self.g,self.p,self.nodes,'storage-token',registry=self.registry,workspace=self.ws,state=self.state,now=NOW)
    def test_failed_storage_persistence_has_zero_mutations(self):
        def fail_save(state):raise CleanupError('disk failure')
        self.ws.save_state=fail_save
        with self.assertRaises(CleanupError):self.submit()
        self.assertEqual([e for e in self.g.events if e[0]=='write'],[])
    def test_lost_storage_response_never_blindly_replays(self):
        def lost(*args,**kwargs):
            self.g._event('write',args[0],args[1],args[2],args[3],None)
            raise GatewayError('object_storage','batch_delete_objects')
        self.g.write=lost
        self.assertEqual(self.submit().status,'unresolved')
        self.assertEqual(self.state.records[self.nodes[0].key]['attempts'][0]['status'],'unresolved')
        with self.assertRaises(CleanupError):self.submit()
        self.assertEqual(len([e for e in self.g.events if e[0]=='write']),1)
    def test_malformed_storage_response_is_unresolved_and_cannot_replay(self):
        def malformed(service,region,operation,params,endpoint=None):
            self.g._event('write',service,region,operation,params,endpoint)
            return None,{}
        self.g.write=malformed
        self.assertEqual(self.submit().status,'unresolved')
        with self.assertRaises(CleanupError):self.submit()
        self.assertEqual(len([e for e in self.g.events if e[0]=='write']),1)

    def test_storage_chunks_one_bucket_at_thousand_and_rejects_history(self):
        base=self.nodes[0];nodes=[replace(base,key=str(i),metadata=dict(base.metadata,object_name=str(i))) for i in range(1001)]
        p=plan_for(nodes,parent='parent',child='child')
        self.assertEqual(sorted(len(g) for g in bulk_groups(p,nodes,self.registry)),[1,1000])
        self.g.bucket['versioning']='Suspended'
        with self.assertRaises(CleanupError):self.submit()
        self.assertEqual([e for e in self.g.events if e[0]=='write'],[])

if __name__=='__main__':unittest.main()
