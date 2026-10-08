"""Offline producer ordering and deletion boundary tests."""
from copy import deepcopy
from dataclasses import replace
import unittest
from compartment_cleanup.model import CleanupError, Node
from compartment_cleanup.handlers.base import Registry
from compartment_cleanup.gateway import Gateway
try:
    from compartment_cleanup.handlers.logging_analytics import LoggingAnalytics
except ImportError:
    LoggingAnalytics = None

P,X,T,R='parent','external','tenancy','region'
KINDS={
 'LogAnalyticsEntity':'log_analytics_entity',
 'LogAnalyticsObjectCollectionRule':'log_analytics_object_collection_rule',
 'LogAnalyticsEmBridge':'log_analytics_em_bridge',
 'ServiceConnector':'service_connector',
 'LogAnalyticsLogGroup':'log_analytics_log_group',
}
LISTS={
 'list_log_analytics_entities':'LogAnalyticsEntity',
 'list_log_analytics_object_collection_rules':'LogAnalyticsObjectCollectionRule',
 'list_log_analytics_em_bridges':'LogAnalyticsEmBridge',
 'list_service_connectors':'ServiceConnector',
}
class AnalyticsGateway:
    def __init__(self):
        self.tenancy_id=T; self.compartment_links={P:T,X:T}; self.cleanup_scope={P}
        self.regions=[R]; self.rows={}; self.events=[]; self.sources=[]; self.associations=[]
        self.namespaces=['ns','second']; self.denied=None; self.lost=False
    def add(self,kind,key,owner=P,namespace='ns',**fields):
        row=dict(id=key,compartment_id=owner,**fields); row.setdefault('lifecycle_state','ACTIVE')
        if kind=='LogAnalyticsEntity':
            row.setdefault('creation_source',{'type':'NONE','details':'untrusted'})
            row.setdefault('associated_sources_count',0); row.setdefault('are_logs_collected',False)
        self.rows[(kind,key)]=(namespace,row); return row
    def read(self,service,region,operation,params,endpoint=None):
        self.events.append(('read',operation,deepcopy(params)))
        if operation==self.denied: raise CleanupError('denied')
        if operation=='list_namespaces':
            assert params=={'compartment_id':T}
            return {'items':[{'namespace_name':n,'compartment_id':T} for n in self.namespaces]},{}
        kind=next(k for k,v in KINDS.items() if operation=='get_'+v)
        key=params[KINDS[kind]+'_id']; namespace,row=self.rows[(kind,key)]
        if kind!='ServiceConnector': assert params['namespace_name']==namespace
        return deepcopy(row),{'etag':'version'}
    def items(self,service,region,operation,params,endpoint=None):
        self.events.append(('items',operation,deepcopy(params)))
        if operation==self.denied: raise CleanupError('denied')
        if operation=='list_entity_associations':
            assert params['direct_or_all_associations']=='ALL'; return deepcopy(self.associations)
        if operation=='list_entity_source_associations':
            assert params['life_cycle_state']=='ALL'; return deepcopy(self.sources)
        kind=LISTS[operation]
        return [deepcopy(row) for (k,_),(ns,row) in self.rows.items() if k==kind
                and row['compartment_id']==params['compartment_id']
                and (kind=='ServiceConnector' or ns==params['namespace_name'])]
    def write(self,service,region,operation,params,endpoint=None):
        self.events.append(('write',operation,deepcopy(params)))
        kind=next(k for k,v in KINDS.items() if operation=='delete_'+v)
        key=params[KINDS[kind]+'_id']
        if kind=='LogAnalyticsEntity':
            # Simulate exact object producers recreating a deleted entity.
            live=any(k=='LogAnalyticsObjectCollectionRule' and row.get('entity_id')==key and row['lifecycle_state']!='DELETED'
                     for (k,_),(_,row) in self.rows.items())
            self.rows[(kind,key)][1]['lifecycle_state']='ACTIVE' if live else 'DELETED'
        else: self.rows[(kind,key)][1]['lifecycle_state']='DELETED'
        if self.lost: raise TimeoutError('response lost')
        return None,{'opc-request-id':'trace'}

def node(kind,key,namespace='ns',owner=P):
    return Node(key,kind,R,owner,'','ACTIVE','','unresolved',{'namespace':namespace})

class AnalyticsTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(LoggingAnalytics,'Logging Analytics handler missing')
        self.g=AnalyticsGateway(); self.h=LoggingAnalytics()
    def entity(self,**fields):
        self.g.add('LogAnalyticsEntity','entity',**fields)
        return node('LogAnalyticsEntity','entity')
    def rule(self,owner=P,**fields):
        self.g.add('LogAnalyticsLogGroup','group')
        self.g.add('LogAnalyticsObjectCollectionRule','rule',owner=owner,entity_id='entity',log_group_id='group',**fields)
        return node('LogAnalyticsObjectCollectionRule','rule',owner=owner)
    def test_all_namespaces_and_exact_rule_edge(self):
        self.entity(); self.rule(); self.g.add('LogAnalyticsEntity','other',namespace='second')
        nodes,edges,probes=self.h.discover(self.g,P,R)
        self.assertEqual({n.key for n in nodes},{'entity','rule','other'})
        self.assertTrue(any(e.before=='rule' and e.after=='entity' for e in edges))
        self.assertEqual({p.status for p in probes},{'complete'})
    def test_producer_terminal_required_and_no_rule_force_flag(self):
        n=self.entity(); r=self.rule()
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
        obs=self.h.inspect(self.g,r,{P}); result=self.h.submit(self.g,r,obs,'attempt')
        self.assertEqual(result.status,'pending')
        self.assertEqual(self.h.inspect(self.g,r,{P}).status,'deleted')
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'present')
        self.assertNotIn('is_force_delete',next(e[2] for e in self.g.events if e[0]=='write'))
        self.assertNotIn('opc_retry_token',next(e[2] for e in self.g.events if e[0]=='write'))
    def test_external_rule_blocks_entity_without_external_node(self):
        n=self.entity(); self.rule(owner=X)
        nodes,edges,_=self.h.discover(self.g,P,R)
        self.assertNotIn('rule',{n.key for n in nodes})
        self.assertTrue(next(n for n in nodes if n.key=='entity').blockers)
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
    def test_source_string_and_free_text_do_not_prove_sch_or_em_mapping(self):
        for source in ('SERVICE_CONNECTOR_HUB','EM_BRIDGE','BULK_DISCOVERY',None):
            with self.subTest(source=source):
                n=self.entity(creation_source={'type':source,'details':'connector'},source_id='connector')
                self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
    def test_ambiguous_rule_mapping_blocks_entity(self):
        n=self.entity(); self.rule(); self.g.rows[('LogAnalyticsObjectCollectionRule','rule')][1].pop('entity_id')
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
    def test_live_connector_candidate_blocks_manual_entity(self):
        n=self.entity(); self.g.add('ServiceConnector','connector',owner=X,target={'kind':'loggingAnalytics','log_group_id':'group'})
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
    def test_bridge_delete_preserves_entities_and_checks_destination(self):
        self.g.add('LogAnalyticsEmBridge','bridge',em_entities_compartment_id=P)
        n=node('LogAnalyticsEmBridge','bridge')
        self.h.submit(self.g,n,self.h.inspect(self.g,n,{P}),'attempt')
        self.assertIs(next(e[2] for e in self.g.events if e[0]=='write')['is_delete_entities'],False)
        self.g.rows[('LogAnalyticsEmBridge','bridge')][1].update(lifecycle_state='ACTIVE',em_entities_compartment_id=X)
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
    def test_rule_external_entity_or_log_group_effect_blocks(self):
        for kind,key in [('LogAnalyticsEntity','entity'),('LogAnalyticsLogGroup','group')]:
            with self.subTest(kind=kind):
                self.entity(); r=self.rule(); self.g.rows[(kind,key)][1]['compartment_id']=X
                self.assertEqual(self.h.inspect(self.g,r,{P}).status,'unresolved')
    def test_connector_external_target_effect_blocks(self):
        self.g.add('LogAnalyticsLogGroup','group',owner=X)
        self.g.add('ServiceConnector','connector',target={'kind':'loggingAnalytics','log_group_id':'group'})
        self.assertEqual(self.h.inspect(self.g,node('ServiceConnector','connector'),{P}).status,'unresolved')
    def test_entity_associations_and_count_conflicts_block_force(self):
        n=self.entity(); self.g.associations=[{'id':'related','compartment_id':X}]
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
        self.g.associations=[]; self.g.sources=[{'entity_id':'entity','source_name':'configuration','log_group_id':'group','agent_id':'agent'}]
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
        self.g.sources=[]; self.g.rows[('LogAnalyticsEntity','entity')][1]['associated_sources_count']=1
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
    def test_entity_delete_rechecks_etag_and_owner_and_disables_force(self):
        n=self.entity(); obs=self.h.inspect(self.g,n,{P})
        self.h.submit(self.g,n,obs,'attempt')
        params=next(e[2] for e in self.g.events if e[0]=='write')
        self.assertEqual((params['if_match'],params['opc_request_id'],params['is_force_delete']),('version','attempt',False))
        self.g.rows[('LogAnalyticsEntity','entity')][1].update(lifecycle_state='ACTIVE',compartment_id=X)
        with self.assertRaises(CleanupError): self.h.submit(self.g,n,obs,'again')
        self.assertEqual(len([e for e in self.g.events if e[0]=='write']),1)
    def test_denied_producer_page_and_missing_get_remain_unresolved(self):
        n=self.entity(); self.g.denied='list_log_analytics_em_bridges'
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
        nodes,_,probes=self.h.discover(self.g,P,R)
        self.assertTrue(any(p.status=='failed' for p in probes))
        self.g.denied=None; del self.g.rows[('LogAnalyticsEntity','entity')]
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
    def test_reappearance_reopens_deleted_record_without_losing_history(self):
        n=self.entity(); obs=self.h.inspect(self.g,n,{P}); self.h.submit(self.g,n,obs,'attempt')
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'deleted')
        self.g.rows[('LogAnalyticsEntity','entity')][1]['lifecycle_state']='ACTIVE'
        nodes,_,_=self.h.discover(self.g,P,R)
        fresh=next(n for n in nodes if n.key=='entity'); self.assertEqual(fresh.lifecycle_state,'ACTIVE')
        record={'status':'deleted','attempts':[{'id':'attempt'}]}
        renewed=self.h.reconcile_record(self.g,fresh,{P},record)
        self.assertEqual(renewed['status'],'present'); self.assertEqual(renewed['attempts'],[{'id':'attempt'}])
    def test_registry_drops_untrusted_nested_details_and_dispatch(self):
        n=self.entity(); n=replace(n,metadata={'namespace':'ns','creation_source':{'type':'NONE','details':'secret'},'operation':'bad'})
        safe=Registry({'logging_analytics':self.h}).classify(n)
        self.assertEqual(safe.metadata,{'namespace':'ns','creation_source_type':'NONE'})
    def test_entity_unsupported_lifecycle_never_authorizes_delete(self):
        n=self.entity(lifecycle_state='INACTIVE')
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
    def test_historical_rule_retained_when_listing_omits_deleted_record(self):
        n=self.entity(); self.rule()
        nodes,_,_=self.h.discover(self.g,P,R)
        previous=next(n for n in nodes if n.key=='entity')
        self.g.rows[('LogAnalyticsObjectCollectionRule','rule')][1]['lifecycle_state']='DELETED'
        original=self.g.items
        def items(service,region,operation,params,endpoint=None):
            return [] if operation=='list_log_analytics_object_collection_rules' else original(service,region,operation,params,endpoint)
        self.g.items=items
        fresh=self.h.refresh_node(self.g,n,previous,{P})
        self.assertEqual(fresh.metadata['producers'][0]['id'],'rule')
        self.assertEqual(self.h.inspect(self.g,fresh,{P}).status,'present')
        self.g.rows[('LogAnalyticsObjectCollectionRule','rule')][1]['lifecycle_state']='ACTIVE'
        self.assertEqual(self.h.inspect(self.g,fresh,{P}).status,'unresolved')
    def test_deleted_producer_missing_relation_keeps_historical_identity(self):
        n=self.entity(); self.rule()
        nodes,_,_=self.h.discover(self.g,P,R)
        previous=next(n for n in nodes if n.key=='entity')
        row=self.g.rows[('LogAnalyticsObjectCollectionRule','rule')][1]
        row['lifecycle_state']='DELETED'; row.pop('entity_id'); row.pop('log_group_id')
        fresh=self.h.refresh_node(self.g,n,previous,{P})
        self.assertEqual(fresh.metadata['producers'],[{'id':'rule','kind':'LogAnalyticsObjectCollectionRule','compartment_id':P,'namespace':'ns'}])
        self.assertEqual(self.h.inspect(self.g,fresh,{P}).status,'present')
    def test_automatic_entity_remains_blocked_after_exact_rule_deleted(self):
        n=self.entity(creation_source={'type':'LOGGING_ANALYTICS','details':'rule'})
        self.rule(); self.g.rows[('LogAnalyticsObjectCollectionRule','rule')][1]['lifecycle_state']='DELETED'
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
    def test_simulated_recreation_prevents_unconditional_delete_progress(self):
        n=self.entity(); self.rule()
        # Exercise the fake service's documented recreation, then real safe handler.
        self.g.write('log_analytics',R,'delete_log_analytics_entity',{'log_analytics_entity_id':'entity'})
        self.assertEqual(self.g.rows[('LogAnalyticsEntity','entity')][1]['lifecycle_state'],'ACTIVE')
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
        r=node('LogAnalyticsObjectCollectionRule','rule')
        self.h.submit(self.g,r,self.h.inspect(self.g,r,{P}),'stop')
        self.h.submit(self.g,n,self.h.inspect(self.g,n,{P}),'delete')
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'deleted')
    def test_lost_delete_response_does_not_fabricate_deleted(self):
        n=self.entity(); self.g.lost=True
        with self.assertRaises(TimeoutError): self.h.submit(self.g,n,self.h.inspect(self.g,n,{P}),'attempt')
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'deleted')
        self.assertEqual(len([e for e in self.g.events if e[0]=='write']),1)
    def test_connector_uses_typed_source_and_target_owners(self):
        self.g.namespaces=['ns']; self.g.add('LogAnalyticsLogGroup','group')
        row=self.g.add('ServiceConnector','connector',target={'kind':'loggingAnalytics','log_group_id':'group'},
                       source={'kind':'logging','log_sources':[{'compartment_id':P,'log_group_id':'logs','log_id':'log'}]})
        n=node('ServiceConnector','connector')
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'present')
        row['source']['log_sources'][0]['compartment_id']=X
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
    def test_sdk_boundaries_emit_non_cascading_flags_and_no_retry_token(self):
        import oci
        from types import SimpleNamespace
        class Transport:
            def __init__(self): self.calls=[]
            def get_preferred_retry_strategy(self,**kwargs): return None
            def call_api(self,**kwargs):
                self.calls.append(kwargs)
                return SimpleNamespace(data=None,headers={})
        client=object.__new__(oci.log_analytics.LogAnalyticsClient)
        client.base_client=Transport(); client.retry_strategy=None
        g=Gateway({'tenancy':T,'region':R}); g._clients[('log_analytics',R,None)]=client
        for operation,identity,flags in [
            ('delete_log_analytics_entity','log_analytics_entity_id',{'is_force_delete':False}),
            ('delete_log_analytics_em_bridge','log_analytics_em_bridge_id',{'is_delete_entities':False}),
            ('delete_log_analytics_object_collection_rule','log_analytics_object_collection_rule_id',{})]:
            g.write('log_analytics',R,operation,dict(namespace_name='ns',if_match='etag',opc_request_id='attempt',**{identity:'resource'},**flags))
        calls=client.base_client.calls
        self.assertIs(calls[0]['query_params']['isForceDelete'],False)
        self.assertIs(calls[1]['query_params']['isDeleteEntities'],False)
        for call in calls:
            self.assertEqual(call['header_params']['if-match'],'etag')
            self.assertNotIn('opc-retry-token',call['header_params'])
    def test_404_after_delete_is_unresolved_not_terminal(self):
        from compartment_cleanup.gateway import GatewayError
        n=self.entity(); self.h.submit(self.g,n,self.h.inspect(self.g,n,{P}),'attempt')
        original=self.g.read
        def read(service,region,operation,params,endpoint=None):
            if operation=='get_log_analytics_entity': raise GatewayError(service,operation,404,'NotAuthorizedOrNotFound')
            return original(service,region,operation,params,endpoint)
        self.g.read=read
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
    def test_gateway_entity_pagination_and_namespace_nonpagination(self):
        class Client:
            def __init__(self): self.calls=[]
            def list_log_analytics_entities(self,**params):
                self.calls.append(params)
                from types import SimpleNamespace
                return SimpleNamespace(data={'items':[{'id':'second' if params.get('page') else 'first'}]},headers={} if params.get('page') else {'opc-next-page':'next'})
        c=Client(); g=Gateway({'tenancy':T,'region':R}); g._clients[('log_analytics',R,None)]=c
        self.assertEqual([r['id'] for r in g.items('log_analytics',R,'list_log_analytics_entities',{'namespace_name':'ns','compartment_id':P})],['first','second'])

if __name__=='__main__': unittest.main()
