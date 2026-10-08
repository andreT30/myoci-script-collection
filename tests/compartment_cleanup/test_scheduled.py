"""Offline scheduled deletion contracts; no live service or secret-content reads."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock
from compartment_cleanup.model import Plan, State, plan_to_dict, state_to_dict
from compartment_cleanup.reporting import render_report
import oci
from compartment_cleanup.model import CleanupError, Node, Edge
from compartment_cleanup.discovery import collapse_cascades, merge_nodes
from compartment_cleanup.handlers.base import Registry
try:
    from compartment_cleanup.handlers.scheduled import ScheduledResources, scheduled_time, validate_cascade
except ImportError:
    ScheduledResources = scheduled_time = validate_cascade = None

P,C,X,T,R = 'parent','child','external','tenancy','region'
NOW = datetime(2026,10,8,tzinfo=timezone.utc)

class ScheduledGateway:
    def __init__(self):
        self.tenancy_id=T; self.home_region=R; self.regions=[R,'other']
        self.compartment_links={P:T,C:P,X:T}; self.cleanup_scope={P,C}
        self.rows={}; self.extra={}; self.events=[]; self.lost=False
        self.confirmed='2026-10-20T12:34:56Z'
    def add(self,kind,key,owner=P,region=R,**fields):
        row=dict(id=key,compartment_id=owner,lifecycle_state='ENABLED' if kind=='Key' else 'ACTIVE',**fields)
        self.rows[(region,kind,key)]=row
        return row
    def read(self,service,region,operation,params,endpoint=None):
        self.events.append(('read',service,region,operation,deepcopy(params),endpoint))
        if operation=='get_namespace': return 'namespace',{}
        if operation=='get_vault_usage':
            return deepcopy(self.extra.get(operation,{'key_count':0,'software_key_count':0})),{}
        kind={'get_certificate':'Certificate','get_certificate_authority':'CertificateAuthority','get_ca_bundle':'CaBundle',
              'get_vault':'Vault','get_key':'Key','get_secret':'Secret','get_load_balancer':'LoadBalancer',
              'get_network_load_balancer':'NetworkLoadBalancer','get_volume':'Volume','get_boot_volume':'BootVolume','get_volume_backup':'VolumeBackup','get_boot_volume_backup':'BootVolumeBackup','get_bucket':'Bucket'}[operation]
        key=params['bucket_name'] if operation=='get_bucket' else next(iter(params.values()))
        row=self.rows.get((region,kind,key))
        if row is None: raise CleanupError('Missing identity')
        return deepcopy(row),{'etag':'etag'}
    def items(self,service,region,operation,params,endpoint=None):
        self.events.append(('items',service,region,operation,deepcopy(params),endpoint))
        if operation in self.extra or (region,operation) in self.extra:
            rows=self.extra.get((region,operation),self.extra.get(operation))
            if isinstance(rows,Exception): raise rows
            if operation=='list_associations':
                return deepcopy([x for x in rows if x['certificates_resource_id']==params['certificates_resource_id']])
            return deepcopy([row for row in rows if not params.get('compartment_id') or row.get('compartment_id')==params['compartment_id']])
        if operation in ('list_associations','list_vault_replicas'): return []
        kind={'list_certificates':'Certificate','list_certificate_authorities':'CertificateAuthority',
              'list_ca_bundles':'CaBundle','list_vaults':'Vault','list_keys':'Key','list_secrets':'Secret','list_volumes':'Volume','list_boot_volumes':'BootVolume','list_volume_backups':'VolumeBackup','list_boot_volume_backups':'BootVolumeBackup','list_buckets':'Bucket'}[operation]
        return [deepcopy(row) for (r,k,_),row in self.rows.items() if r==region and k==kind
                and (not params.get('compartment_id') or row['compartment_id']==params['compartment_id'])
                and (kind!='Key' or row.get('vault_id')==next((v['id'] for (vr,vk,_),v in self.rows.items() if vr==region and vk=='Vault' and v.get('management_endpoint')==endpoint),row.get('vault_id')))
                and (not params.get('issuer_certificate_authority_id') or row.get('issuer_certificate_authority_id')==params['issuer_certificate_authority_id'])]
    def write(self,service,region,operation,params,endpoint=None):
        self.events.append(('write',service,region,operation,deepcopy(params),endpoint))
        kind={'schedule_certificate_deletion':'Certificate','schedule_certificate_authority_deletion':'CertificateAuthority',
              'schedule_vault_deletion':'Vault','schedule_key_deletion':'Key','schedule_secret_deletion':'Secret',
              'delete_ca_bundle':'CaBundle'}[operation]
        key=next(v for k,v in params.items() if k.endswith('_id') and k!='opc_request_id')
        row=self.rows[(region,kind,key)]
        row['lifecycle_state']='DELETING' if kind=='CaBundle' else 'PENDING_DELETION'
        if kind!='CaBundle': row['time_of_deletion']=self.confirmed
        if self.lost: raise TimeoutError('response lost')
        return None,{'opc-request-id':'trace'}

def node(kind,key,metadata=None,region=R,owner=P):
    return Node(key,kind,region,owner,'','ACTIVE','','unresolved',metadata or {})

class ScheduledTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(ScheduledResources, "Scheduled deletion handler is missing")
        self.g=ScheduledGateway(); self.h=ScheduledResources()
    def cert(self,key='cert',**fields):
        self.g.add('Certificate',key,**fields)
        return node('Certificate',key)
    def vault(self,key='vault',owner=P,**fields):
        self.g.add('Vault',key,owner=owner,management_endpoint='https://verified.endpoint',vault_type='DEFAULT',is_primary=True,**fields)
        return node('Vault',key,{'management_endpoint':'https://verified.endpoint','vault_type':'DEFAULT','is_primary':True},owner=owner)
    def key(self,key='key',owner=P,**fields):
        self.g.add('Key',key,owner=owner,vault_id='vault',protection_mode='HSM',is_primary=True,**fields)
        return node('Key',key,{'vault_id':'vault','protection_mode':'HSM','is_primary':True},owner=owner)
    def secret(self,**fields):
        self.vault(); self.key()
        self.g.add('Secret','secret',vault_id='vault',key_id='key',is_replica=False,**fields)
        return node('Secret','secret',{'vault_id':'vault','key_id':'key','is_replica':False})
    def test_minimums_and_utc(self):
        for kind,expected in [('Certificate',9),('Secret',9),('CertificateAuthority',15),('Vault',15),('Key',15)]:
            self.assertEqual(scheduled_time(kind,NOW),datetime(2026,10,expected,0,5,tzinfo=timezone.utc))
        with self.assertRaises(CleanupError): scheduled_time('Key',datetime(2026,10,8))
    def test_schedule_once_readback_service_date_trace_not_work_request(self):
        n=self.cert(); obs=self.h.inspect(self.g,n,{P,C})
        result=self.h.submit(self.g,n,obs,'attempt')
        self.assertEqual((result.status,result.scheduled_at,result.request_id),('pending','2026-10-20T12:34:56Z','trace'))
        with self.assertRaises(CleanupError): self.h.submit(self.g,n,obs,'attempt2')
        writes=[e for e in self.g.events if e[0]=='write']; self.assertEqual(len(writes),1)
        self.assertNotIn('opc_retry_token',writes[0][4]); self.assertEqual(writes[0][4]['if_match'],'etag')
    def test_pending_dates_preserved_even_after_deadline_and_missing_date(self):
        n=self.cert(); row=self.g.rows[(R,'Certificate','cert')]
        for state in ('PENDING_DELETION','SCHEDULING_DELETION','DELETING'):
            row.update(lifecycle_state=state,time_of_deletion='2020-01-01T00:00:00Z')
            obs=self.h.inspect(self.g,n,{P}); self.assertEqual((obs.status,obs.scheduled_at),('pending','2020-01-01T00:00:00Z'))
            row.pop('time_of_deletion'); self.assertEqual(self.h.inspect(self.g,n,{P}).status,'pending')
        row['lifecycle_state']='FAILED'; self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
        row['lifecycle_state']='DELETED'; self.assertEqual(self.h.inspect(self.g,n,{P}).status,'deleted')
        del self.g.rows[(R,'Certificate','cert')]; self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
    def test_lost_response_reconciles_without_repeat(self):
        n=self.cert(); obs=self.h.inspect(self.g,n,{P}); self.g.lost=True
        with self.assertRaises(TimeoutError): self.h.submit(self.g,n,obs,'attempt')
        self.assertEqual(self.h.inspect(self.g,n,{P}).scheduled_at,'2026-10-20T12:34:56Z')
        with self.assertRaises(CleanupError): self.h.submit(self.g,n,obs,'attempt')
        self.assertEqual(len([e for e in self.g.events if e[0]=='write']),1)
    def test_external_association_uses_consumer_owner_and_typed_tls(self):
        n=self.cert(); lb='ocid1.loadbalancer.oc1.region.lb'
        self.g.add('LoadBalancer',lb,owner=X,listeners={'tls':{'ssl_configuration':{'certificate_ids':['cert']}}})
        self.g.extra['list_associations']=[dict(id='a',compartment_id=P,certificates_resource_id='cert',associated_resource_id=lb,association_type='CERTIFICATE',lifecycle_state='ACTIVE')]
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
        nodes,edges,_=self.h.discover(self.g,P,R)
        self.assertTrue(next(x for x in nodes if x.key=='cert').blockers)
        self.assertTrue(all('compartment_id' not in e[4] for e in self.g.events if e[3]=='list_associations'))
        self.g.rows[(R,'LoadBalancer',lb)]['compartment_id']=P
        nodes,edges,_=self.h.discover(self.g,P,R)
        self.assertIn(Edge(lb,'cert','Typed certificate consumer'),edges)
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
        self.g.extra['list_associations']=[]; self.assertEqual(self.h.inspect(self.g,n,{P}).status,'present')
    def test_issued_child_without_compartment_filter_blocks_ca(self):
        self.g.add('CertificateAuthority','ca',kms_key_id='retained')
        self.g.add('Certificate','foreign',owner=X,issuer_certificate_authority_id='ca')
        n=node('CertificateAuthority','ca',{'kms_key_id':'retained'})
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
        self.assertTrue(all('compartment_id' not in e[4] for e in self.g.events if e[4].get('issuer_certificate_authority_id')))
    def test_vault_full_key_proof_collapse_and_unknown_count(self):
        self.vault(); self.key(); self.g.extra['get_vault_usage']={'key_count':1,'software_key_count':0}
        nodes,edges,_=self.h.discover(self.g,P,R)
        by={n.key:n for n in nodes}; self.assertEqual(by['key'].action,'cascade')
        self.assertEqual(by['vault'].metadata['cascade_members'],['key'])
        compartments={x:node('Compartment',x,owner=T) for x in (P,C)}
        normalized,new_edges=collapse_cascades(dict(by,**compartments,consumer=node('Certificate','consumer')),edges+[Edge('consumer','key','encrypted')])
        self.assertIn(Edge('consumer','vault','encrypted'),new_edges)
        self.g.extra['get_vault_usage']['software_key_count']=None
        self.assertEqual(self.h.inspect(self.g,by['vault'],{P,C}).status,'unresolved')
        self.assertEqual(self.h.inspect(self.g,node('Key','key',by['key'].metadata),{P,C}).status,'present')
    def test_foreign_key_blocks_vault_but_not_individual_key_and_replicas_block_both(self):
        v=self.vault(); k=self.key(); self.key('foreign',owner=X)
        self.g.extra['get_vault_usage']={'key_count':2,'software_key_count':0}
        self.assertEqual(self.h.inspect(self.g,v,{P,C}).status,'unresolved')
        self.assertEqual(self.h.inspect(self.g,k,{P,C}).status,'present')
        self.g.extra['list_vault_replicas']=[{'region':'other','status':'ACTIVE','management_endpoint':'https://other'}]
        self.assertEqual(self.h.inspect(self.g,k,{P,C}).status,'unresolved')
    def test_secret_regional_same_ocid_replica_validation_and_content_omission(self):
        targets={'replication_targets':[{'target_region':'other','target_vault_id':'targetv','target_key_id':'targetk'}]}
        n=self.secret(replication_config=targets,metadata={'content':'deep-secret-sentinel'},secret_content={'content':'deep-secret-sentinel'})
        self.g.add('Vault','targetv',region='other',management_endpoint='https://other',vault_type='DEFAULT',is_primary=True)
        self.g.add('Key','targetk',region='other',vault_id='targetv',protection_mode='HSM',is_primary=True)
        replica=self.g.add('Secret','secret',region='other',vault_id='vault',key_id='key',is_replica=True,
                          source_region_information={'source_region':R,'source_vault_id':'vault','source_key_id':'key'})
        source_nodes,_,_=self.h.discover(self.g,P,R); replica_nodes,_,_=self.h.discover(self.g,P,'other')
        secrets=[x for x in merge_nodes([],source_nodes+replica_nodes).values() if x.resource_type=='Secret']
        self.assertEqual(len(secrets),1); self.assertEqual(secrets[0].region,R)
        self.assertNotIn('deep-secret-sentinel',json.dumps([x.metadata for x in source_nodes+replica_nodes]))
        self.assertEqual(self.h.inspect(self.g,secrets[0],{P,C}).status,'present')
        replica['compartment_id']=X; self.assertEqual(self.h.inspect(self.g,secrets[0],{P,C}).status,'unresolved')
    def test_secret_positive_source_deleted_requires_replica_deleted(self):
        n=self.secret(replication_config={'replication_targets':[{'target_region':'other','target_vault_id':'targetv','target_key_id':'targetk'}]})
        self.g.rows[(R,'Secret','secret')]['lifecycle_state']='DELETED'
        self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
    def test_ca_bundle_immediate_conditional_and_404_unresolved(self):
        self.g.add('CaBundle','bundle'); n=node('CaBundle','bundle')
        result=self.h.submit(self.g,n,self.h.inspect(self.g,n,{P}),'attempt'); self.assertEqual(result.status,'pending')
        self.g.rows[(R,'CaBundle','bundle')]['lifecycle_state']='DELETED'; self.assertEqual(self.h.inspect(self.g,n,{P}).status,'deleted')
        del self.g.rows[(R,'CaBundle','bundle')]; self.assertEqual(self.h.inspect(self.g,n,{P}).status,'unresolved')
    def test_all_actual_sdk_schedule_payloads_and_allowed_kwargs(self):
        self.vault(); self.key(); self.secret(); self.cert(); self.g.add('CertificateAuthority','ca')
        contracts=[('Certificate','cert','certificates','ScheduleCertificateDeletionDetails','schedule_certificate_deletion'),
                   ('CertificateAuthority','ca','certificates','ScheduleCertificateAuthorityDeletionDetails','schedule_certificate_authority_deletion'),
                   ('Vault','vault','kms_vault','ScheduleVaultDeletionDetails','schedule_vault_deletion'),
                   ('Key','key','kms_management','ScheduleKeyDeletionDetails','schedule_key_deletion'),
                   ('Secret','secret','vault','ScheduleSecretDeletionDetails','schedule_secret_deletion')]
        self.g.extra['get_vault_usage']={'key_count':1,'software_key_count':0}
        for kind,key,service,model,operation in contracts:
            with self.subTest(kind=kind):
                self.g.rows[(R,'Secret','secret')]['lifecycle_state']='DELETED' if kind in ('Vault','Key') else 'ACTIVE'
                if kind=='Key': self.g.rows[(R,'Vault','vault')]['lifecycle_state']='ACTIVE'
                row=self.g.rows[(R,kind,key)]; n=node(kind,key,{k:v for k,v in row.items() if k not in ('id','compartment_id','lifecycle_state')})
                self.h.submit(self.g,n,self.h.inspect(self.g,n,{P,C}),'attempt')
                event=next(e for e in reversed(self.g.events) if e[0]=='write')
                payload=next(v for k,v in event[4].items() if k.endswith('_details'))
                self.assertEqual(type(payload).__name__,model)
                serializer=object.__new__(oci.base_client.BaseClient); serializer.complex_type_mappings={}
                serialized=serializer.sanitize_for_serialization(payload)
                self.assertEqual(set(serialized),{'timeOfDeletion'}); self.assertTrue(serialized['timeOfDeletion'].endswith('Z'))
                self.assertEqual('opc_retry_token' in event[4],kind in ('Vault','Key'))
                cls={'certificates':oci.certificates_management.CertificatesManagementClient,'kms_vault':oci.key_management.KmsVaultClient,'kms_management':oci.key_management.KmsManagementClient,'vault':oci.vault.VaultsClient}[service]
                client=object.__new__(cls); client.base_client=Mock(); client.base_client.get_preferred_retry_strategy.return_value=None; client.retry_strategy=None
                getattr(client,operation)(**event[4])
                actual=client.base_client.call_api.call_args.kwargs
                self.assertEqual(actual['body'],payload); self.assertEqual(actual['header_params']['if-match'],'etag')

    def plan(self,nodes,edges=()):
        comp={P:Node(P,'Compartment',R,T,'','ACTIVE','compartment','retain',{}),C:Node(C,'Compartment',R,P,'','ACTIVE','compartment','delete',{})}
        return Plan(1,T,P,R,'2026-10-08T00:00:00Z',{P:T,C:P},dict(comp,**{n.key:n for n in nodes}),list(edges),[],{}, {})
    def test_association_unknown_type_state_or_missing_corroboration_blocks(self):
        n=self.cert(); lb='ocid1.loadbalancer.oc1.region.lb'
        self.g.add('LoadBalancer',lb,listeners={'tls':{'ssl_configuration':{'certificate_ids':['cert']}}})
        row=dict(id='a',compartment_id=P,certificates_resource_id='cert',associated_resource_id=lb,association_type='CERTIFICATE',lifecycle_state='ACTIVE')
        self.g.extra['list_associations']=[row]
        for field,value in [('association_type','CERTIFICATE_AUTHORITY'),('association_type',None),('lifecycle_state','UNKNOWN_ENUM_VALUE'),('lifecycle_state',None)]:
            bad=dict(row,**{field:value}); self.g.extra['list_associations']=[bad]
            nodes,_,_=self.h.discover(self.g,P,R)
            self.assertTrue(next(x for x in nodes if x.key=='cert').blockers)
    def test_report_initial_pending_service_date_without_journal(self):
        n=self.cert(); self.g.rows[(R,'Certificate','cert')].update(lifecycle_state='PENDING_DELETION',time_of_deletion='2026-10-20T12:34:56Z')
        nodes,edges,_=self.h.discover(self.g,P,R); plan=self.plan(nodes,edges)
        self.assertIn('2026-10-20T12:34:56Z',render_report(plan,State(1,T,P,{})))
    def test_whole_artifact_secret_content_omission_and_journal_history(self):
        n=self.secret(metadata={'nested':{'content':'deep-secret-sentinel'}},freeform_tags={'secret':'deep-secret-sentinel'},secret_content={'content':'deep-secret-sentinel'})
        nodes,edges,_=self.h.discover(self.g,P,R); plan=self.plan(nodes,edges)
        secret=next(x for x in nodes if x.key=='secret')
        record=self.h.reconcile_record(self.g,secret,{P,C},{'attempts':[{'id':'history'}]})
        state=State(1,T,P,{'secret':record})
        self.assertEqual(record['attempts'],[{'id':'history'}])
        self.assertNotIn('deep-secret-sentinel',json.dumps(plan_to_dict(plan))+json.dumps(state_to_dict(state))+render_report(plan,state))
    def test_classification_drops_nested_artifact_secret_content(self):
        n=node('Secret','secret',{'vault_id':'vault','key_id':'key','is_replica':False,'regional_replicas':[{'id':'secret','region':'other','secret_content':{'content':'deep-secret-sentinel'}}]})
        safe=Registry({'scheduled':self.h}).classify(n)
        self.assertNotIn('deep-secret-sentinel',json.dumps(safe.metadata))
    def test_unreadable_source_replica_is_explicit_unresolved_synthetic_identity(self):
        self.g.add('Secret','secret',region='other',is_replica=True,source_region_information={'source_region':R,'source_vault_id':'v','source_key_id':'k'})
        nodes,_,_=self.h.discover(self.g,P,'other')
        replicas=[x for x in nodes if x.resource_type=='SecretReplica']
        self.assertEqual(len(replicas),1); self.assertEqual(replicas[0].action,'unresolved')
        self.assertNotEqual(replicas[0].key,'secret')
    def test_key_crosscomp_external_vault_does_not_inherit_owner(self):
        self.vault(owner=X); self.key(owner=P)
        nodes,_,probes=self.h.discover(self.g,P,R)
        key=next(x for x in nodes if x.key=='key')
        self.assertEqual(key.compartment_id,P); self.assertEqual(key.action,'schedule')
        self.assertEqual(self.h.inspect(self.g,key,{P,C}).status,'present')
        self.h.submit(self.g,key,self.h.inspect(self.g,key,{P,C}),'attempt')
        self.assertEqual([e[5] for e in self.g.events if e[0]=='write'],['https://verified.endpoint'])
    def test_ca_crl_effect_unknown_blocks_without_persisting_configuration(self):
        self.g.add('CertificateAuthority','ca',certificate_revocation_list_details={'object_storage_config':{'object_storage_bucket_name':'unknown-bucket'}})
        nodes,_,_=self.h.discover(self.g,P,R); ca=next(x for x in nodes if x.key=='ca')
        self.assertTrue(ca.blockers); self.assertNotIn('unknown-bucket',json.dumps(ca.metadata))
    def test_vault_preserves_later_pending_key_date_instead_of_rescheduling(self):
        v=self.vault(); self.key(); self.g.extra['get_vault_usage']={'key_count':1,'software_key_count':0}
        row=self.g.rows[(R,'Key','key')]; row.update(lifecycle_state='PENDING_DELETION',time_of_deletion=(datetime.now(timezone.utc)+timedelta(days=12)).isoformat())
        old=row['time_of_deletion']; obs=self.h.inspect(self.g,v,{P,C}); self.assertEqual(obs.status,'present')
        self.h.submit(self.g,v,obs,'attempt')
        event=next(e for e in self.g.events if e[0]=='write')
        self.assertEqual(event[4]['schedule_vault_deletion_details'].time_of_deletion,datetime.fromisoformat(old))
        self.assertEqual(row['time_of_deletion'],old)
    def test_vault_count_bool_and_missing_and_external_mode_block(self):
        v=self.vault(); self.key(); self.g.extra['get_vault_usage']={'key_count':1,'software_key_count':0}
        for field,value in [('key_count',True),('software_key_count',None),('key_count',2)]:
            self.g.extra['get_vault_usage']={'key_count':1,'software_key_count':0}; self.g.extra['get_vault_usage'][field]=value
            self.assertEqual(self.h.inspect(self.g,v,{P,C}).status,'unresolved')
        self.g.rows[(R,'Key','key')]['protection_mode']='EXTERNAL'
        self.assertEqual(self.h.inspect(self.g,v,{P,C}).status,'unresolved')
    def test_no_etag_or_moved_owner_cannot_schedule(self):
        n=self.cert(); obs=self.h.inspect(self.g,n,{P,C})
        self.g.rows[(R,'Certificate','cert')]['compartment_id']=X
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'moved')
        with self.assertRaises(CleanupError): self.h.submit(self.g,n,obs,'attempt')
        self.assertFalse(any(e[0]=='write' for e in self.g.events))
    def test_source_secret_can_retain_fresh_external_encryption_dependencies(self):
        self.vault(owner=X); self.key(owner=X)
        self.g.add('Secret','secret',vault_id='vault',key_id='key',is_replica=False)
        n=node('Secret','secret',{'vault_id':'vault','key_id':'key','is_replica':False})
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'present')
        self.h.submit(self.g,n,self.h.inspect(self.g,n,{P,C}),'attempt')
        self.assertEqual([e[3] for e in self.g.events if e[0]=='write'],['schedule_secret_deletion'])
    def test_empty_present_crl_configuration_blocks(self):
        self.g.add('CertificateAuthority','ca',certificate_revocation_list_details={})
        self.assertEqual(self.h.inspect(self.g,node('CertificateAuthority','ca'),{P,C}).status,'unresolved')
    def replicated_secret(self):
        targets={'replication_targets':[{'target_region':'other','target_vault_id':'targetv','target_key_id':'targetk'}]}
        self.secret(replication_config=targets)
        self.g.add('Vault','targetv',region='other',management_endpoint='https://other',vault_type='DEFAULT',is_primary=True)
        self.g.add('Key','targetk',region='other',vault_id='targetv',protection_mode='HSM',is_primary=True)
        self.g.add('Secret','secret',region='other',vault_id='vault',key_id='key',is_replica=True,
                   source_region_information={'source_region':R,'source_vault_id':'vault','source_key_id':'key'})
        nodes,_,_=self.h.discover(self.g,P,R)
        return next(n for n in nodes if n.key=='secret')
    def test_secret_holds_target_key_and_vault_until_group_deletion(self):
        self.replicated_secret(); nodes,edges,_=self.h.discover(self.g,P,R)
        self.assertIn(Edge('secret','targetk','Typed secret replica encryption key'),edges)
        self.assertIn(Edge('secret','targetv','Typed secret replica vault'),edges)
    def test_secret_source_and_all_known_replicas_require_positive_deleted(self):
        n=self.replicated_secret(); source=self.g.rows[(R,'Secret','secret')]; replica=self.g.rows[('other','Secret','secret')]
        source['lifecycle_state']='DELETED'
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'unresolved')
        replica['lifecycle_state']='DELETED'; self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'deleted')
        source.pop('replication_config'); self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'deleted')
        del self.g.rows[('other','Secret','secret')]; self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'unresolved')
    def test_unknown_replica_state_or_bad_target_key_vault_blocks_source(self):
        n=self.replicated_secret(); replica=self.g.rows[('other','Secret','secret')]
        replica['lifecycle_state']='UNKNOWN_ENUM_VALUE'
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'unresolved')
        replica['lifecycle_state']='ACTIVE'; self.g.rows[('other','Key','targetk')]['vault_id']='wrong'
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'unresolved')
    def test_pending_vault_does_not_allow_fresh_individual_key_schedule(self):
        self.vault(); k=self.key(); self.g.rows[(R,'Vault','vault')]['lifecycle_state']='PENDING_DELETION'
        self.assertEqual(self.h.inspect(self.g,k,{P,C}).status,'unresolved')

    def test_external_supported_key_consumers_block_key_and_vault_cascade(self):
        for kind,fields in [('Volume',{'kms_key_id':'key'}),('BootVolume',{'kms_key_id':'key'}),('VolumeBackup',{'kms_key_id':'key'}),('BootVolumeBackup',{'kms_key_id':'key'}),('CertificateAuthority',{'kms_key_id':'key'}),('Secret',{'vault_id':'vault','key_id':'key','is_replica':False}),('Bucket',{'name':'consumer','namespace':'namespace','kms_key_id':'key'})]:
            with self.subTest(kind=kind):
                self.g=ScheduledGateway(); v=self.vault(); k=self.key(); self.g.extra['get_vault_usage']={'key_count':1,'software_key_count':0}
                self.g.add(kind,'consumer',owner=X,**fields)
                self.assertEqual(self.h.inspect(self.g,k,{P,C}).status,'unresolved')
                self.assertEqual(self.h.inspect(self.g,v,{P,C}).status,'unresolved')
    def test_live_in_scope_consumers_order_before_key_and_block_submit(self):
        v=self.vault(); k=self.key(); self.g.extra['get_vault_usage']={'key_count':1,'software_key_count':0}
        consumer=self.g.add('Volume','consumer',kms_key_id='key')
        nodes,edges,_=self.h.discover(self.g,P,R)
        self.assertIn(Edge('consumer','key','Typed KMS consumer'),edges)
        vault=next(x for x in nodes if x.key=='vault')
        self.assertEqual(self.h.inspect(self.g,vault,{P,C}).status,'unresolved')
        consumer['lifecycle_state']='TERMINATED'
        self.assertEqual(self.h.inspect(self.g,vault,{P,C}).status,'present')
    def test_denied_reverse_consumer_inventory_blocks_key(self):
        self.vault(); k=self.key(); self.g.extra['list_volume_backups']=CleanupError('Denied second page')
        self.assertEqual(self.h.inspect(self.g,k,{P,C}).status,'unresolved')
    def test_replica_target_key_external_source_consumer_blocks_target_key(self):
        self.vault(); k=self.key()
        self.g.add('Secret','foreign',owner=X,region='other',vault_id='elsewhere',key_id='otherkey',is_replica=False,
                   replication_config={'replication_targets':[{'target_region':R,'target_vault_id':'vault','target_key_id':'key'}]})
        self.assertEqual(self.h.inspect(self.g,k,{P,C}).status,'unresolved')

    def test_recorded_reverse_consumer_list_omission_requires_positive_terminal_get(self):
        self.vault(); self.key(); self.g.extra['get_vault_usage']={'key_count':1,'software_key_count':0}
        consumer=self.g.add('Volume','consumer',kms_key_id='key')
        nodes,_,_=self.h.discover(self.g,P,R); vault=next(x for x in nodes if x.key=='vault')
        self.g.extra['list_volumes']=[]
        self.assertEqual(self.h.inspect(self.g,vault,{P,C}).status,'unresolved')
        consumer['lifecycle_state']='TERMINATED'; self.assertEqual(self.h.inspect(self.g,vault,{P,C}).status,'present')
        del self.g.rows[(R,'Volume','consumer')]; self.assertEqual(self.h.inspect(self.g,vault,{P,C}).status,'unresolved')
    def test_vault_cascade_changes_require_refresh_and_forged_action_cannot_submit(self):
        self.vault(); self.key(); self.g.extra['get_vault_usage']={'key_count':1,'software_key_count':0}
        nodes,_,_=self.h.discover(self.g,P,R); vault=next(x for x in nodes if x.key=='vault')
        self.key('new'); self.g.extra['get_vault_usage']['key_count']=2
        self.assertEqual(self.h.inspect(self.g,vault,{P,C}).status,'unresolved')
        forged=replace(next(x for x in nodes if x.key=='key'),action='schedule',handler='evil')
        safe=Registry({'scheduled':self.h}).classify(forged); self.assertEqual(safe.action,'cascade')
        with self.assertRaises(CleanupError): self.h.submit(self.g,safe,self.h.inspect(self.g,safe,{P,C}),'attempt')
        self.assertFalse(any(e[0]=='write' for e in self.g.events))
    def test_etag_drift_and_fresh_secret_target_scope_change_block_writes(self):
        n=self.replicated_secret(); obs=self.h.inspect(self.g,n,{P,C})
        self.g.rows[('other','Vault','targetv')]['compartment_id']=X
        with self.assertRaises(CleanupError): self.h.submit(self.g,n,obs,'attempt')
        self.assertFalse(any(e[0]=='write' for e in self.g.events))
    def test_pending_unknown_schedule_and_exact_offset_timestamp_reconcile(self):
        n=self.cert(); row=self.g.rows[(R,'Certificate','cert')]
        row.update(lifecycle_state='SCHEDULING_DELETION',time_of_deletion=None)
        record=self.h.reconcile_record(self.g,n,{P},{'attempts':[{'id':'lost'}]})
        self.assertEqual(record['status'],'pending'); self.assertNotIn('scheduled_at',record)
        row.update(lifecycle_state='PENDING_DELETION',time_of_deletion='2026-10-20T12:34:56+00:00')
        self.assertEqual(self.h.inspect(self.g,n,{P}).scheduled_at,'2026-10-20T12:34:56+00:00')

    def test_bucket_summary_without_ocid_uses_canonical_typed_get(self):
        self.vault(); self.key(); self.g.extra['get_vault_usage']={'key_count':1,'software_key_count':0}
        self.g.add('Bucket','bucket-ocid',name='bucket-name',namespace='namespace',kms_key_id='key')
        self.g.rows[(R,'Bucket','bucket-name')]=self.g.rows.pop((R,'Bucket','bucket-ocid'))
        self.g.extra[(R,'list_buckets')]=[{'namespace':'namespace','name':'bucket-name','compartment_id':P}]
        nodes,edges,_=self.h.discover(self.g,P,R)
        self.assertIn(Edge('bucket-ocid','key','Typed KMS consumer'),edges)
        self.assertFalse(next(x for x in nodes if x.key=='vault').blockers)
    def test_refresh_retains_known_secret_regions_when_source_configuration_disappears(self):
        old=self.replicated_secret(); self.g.rows[(R,'Secret','secret')].update(lifecycle_state='DELETED',replication_config=None)
        nodes,_,_=self.h.discover(self.g,P,R); fresh=next(x for x in nodes if x.key=='secret')
        self.assertIsNotNone(getattr(self.h,'refresh_node',None),'Scheduled refresh reconciliation is missing')
        refreshed=self.h.refresh_node(self.g,fresh,old,{P,C})
        self.assertEqual(refreshed.metadata['replication_targets'],old.metadata['replication_targets'])
        self.assertEqual(self.h.inspect(self.g,refreshed,{P,C}).status,'unresolved')
        self.g.rows[('other','Secret','secret')]['lifecycle_state']='DELETED'
        self.assertIsNotNone(getattr(self.h,'refresh_node',None),'Scheduled refresh reconciliation is missing')
        refreshed=self.h.refresh_node(self.g,fresh,old,{P,C})
        self.assertEqual(self.h.inspect(self.g,refreshed,{P,C}).status,'deleted')
    def test_refresh_keeps_known_consumer_get_proof_when_list_omits_it(self):
        self.vault(); self.key(); self.g.extra['get_vault_usage']={'key_count':1,'software_key_count':0}
        self.g.add('Volume','consumer',kms_key_id='key')
        nodes,_,_=self.h.discover(self.g,P,R); old=next(x for x in nodes if x.key=='vault')
        self.g.extra['list_volumes']=[]
        nodes,_,_=self.h.discover(self.g,P,R); fresh=next(x for x in nodes if x.key=='vault')
        self.assertIsNotNone(getattr(self.h,'refresh_node',None),'Scheduled refresh reconciliation is missing')
        refreshed=self.h.refresh_node(self.g,fresh,old,{P,C})
        self.assertTrue(refreshed.metadata['key_consumers'])
        self.assertEqual(self.h.inspect(self.g,refreshed,{P,C}).status,'unresolved')
