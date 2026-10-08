"""Object Storage scope, exact-version operations and durable completion evidence."""
import unittest
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
import oci
from compartment_cleanup.gateway import Gateway, GatewayError
from compartment_cleanup.handlers import storage
from compartment_cleanup.model import CleanupError
from simulator import StorageSimulator

R='eu-frankfurt-1'


def obj(name='a', version=None, marker=False):
    row={'name':name,'etag':'etag-'+(version or name),'time_created':'2026-10-02T00:00:00+00:00',
         'time_modified':'2026-10-02T00:00:00+00:00'}
    if version:row.update(version_id=version,is_delete_marker=marker)
    return row


class StorageTests(unittest.TestCase):
    def setUp(self):self.g=StorageSimulator();self.h=storage.Storage(now=lambda:self.g.now)
    def discover(self):return self.h.discover(self.g,'child',R)
    def node(self,kind):return next(n for n in self.discover()[0] if n.resource_type==kind)
    def writes(self):return [e for e in self.g.events if e[0]=='write']
    def add_object(self):self.g.inventory['list_objects']=[obj()];return self.node('ObjectStorageObject')

    def test_full_pages_preserve_two_versions_marker_and_upload(self):
        self.g.bucket['versioning']='Enabled'
        self.g.set_pages('object_storage',R,'list_object_versions',[([obj(version='v1')],{}),([obj(version='v2'),obj(version='marker',marker=True)],{})])
        self.g.set_pages('object_storage',R,'list_multipart_uploads',[([],{}),([{'object':'pending','upload_id':'u','time_created':'2026-10-02T00:00:00+00:00','namespace':'canonical','bucket':'bucket'}],{})])
        nodes,edges,probes=self.discover()
        self.assertEqual(len({n.key for n in nodes}),5)
        self.assertEqual(sum(n.resource_type=='ObjectStorageVersion' for n in nodes),3)
        self.assertEqual(len(edges),4);self.assertTrue(all(p.status=='complete' for p in probes))

    def test_failed_page_keeps_bucket_blocked_and_failed_probe(self):
        self.g.pages[('object_storage',R,'list_object_versions')]=[([obj(version='v')],{}),GatewayError('object_storage','list_object_versions',403)]
        nodes,_,probes=self.discover()
        self.assertTrue(nodes[0].blockers);self.assertTrue(any(p.status=='failed' for p in probes))

    def test_immutable_bucket_recreation_and_missing_identity_never_write(self):
        for field,value in [('id','ocid1.bucket.oc1..new'),('time_created','2026-10-03T00:00:00+00:00'),('id',None),('namespace','foreign'),('compartment_id','external')]:
            with self.subTest(field=field):
                self.setUp();node=self.add_object();self.g.bucket[field]=value
                observation=self.h.inspect(self.g,node,{'parent','child'})
                self.assertIn(observation.status,('unresolved','moved'))
                with self.assertRaises(CleanupError):self.h.submit(self.g,node,observation,'attempt')
                self.assertFalse(self.writes())

    def test_canonical_namespace_changed_blocks_saved_child(self):
        node=self.add_object();self.g.namespace='new'
        self.assertEqual(self.h.inspect(self.g,node,{'child'}).status,'unresolved')

    def test_new_object_version_or_upload_blocks_saved_branch(self):
        for op,row in [('list_objects',obj('new')),('list_object_versions',obj(version='new')),('list_multipart_uploads',{'object':'a','upload_id':'new','time_created':'2026-10-02T00:00:00+00:00','namespace':'canonical','bucket':'bucket'})]:
            with self.subTest(op=op):
                self.setUp();node=self.add_object();self.g.inventory[op].append(row)
                self.assertEqual(self.h.inspect(self.g,node,{'child'}).status,'unresolved')

    def test_version_head_precondition_exact_kwargs_and_positive_proof(self):
        self.g.bucket['versioning']='Enabled';self.g.inventory['list_object_versions']=[obj(version='v1'),obj(version='v2')]
        node=next(n for n in self.discover()[0] if n.metadata.get('version_id')=='v1')
        obs=self.h.inspect(self.g,node,{'child'});self.assertEqual(obs.status,'present')
        result=self.h.submit(self.g,node,obs,'attempt')
        self.assertEqual(self.writes()[-1][4],{'namespace_name':'canonical','bucket_name':'bucket','object_name':'a','version_id':'v1','if_match':'etag-v1','opc_client_request_id':'attempt'})
        self.assertIsNone(result.request_id)
        self.assertEqual(result.operation_evidence['version_id'],'v1')
        self.assertEqual(self.h.reconcile_submission(self.g,node,result.operation_evidence,{'child'}).status,'deleted')
        self.assertEqual([r['version_id'] for r in self.g.inventory['list_object_versions']],['v2'])

    def test_marker_uses_fresh_paginated_summary_without_head_404_inference(self):
        self.g.bucket['versioning']='Enabled';self.g.inventory['list_object_versions']=[obj(version='marker',marker=True)]
        node=self.node('ObjectStorageVersion');obs=self.h.inspect(self.g,node,{'child'})
        self.assertEqual(obs.status,'present');self.h.submit(self.g,node,obs,'attempt')
        self.assertFalse(any(e[3]=='head_object' for e in self.g.events))
        self.assertEqual(self.writes()[-1][4]['version_id'],'marker')

    def test_changed_version_etag_and_malformed_head_block(self):
        node=self.add_object();self.g.inventory['list_objects'][0]['etag']='new'
        self.assertEqual(self.h.inspect(self.g,node,{'child'}).status,'unresolved')
        self.setUp();node=self.add_object();read=self.g.read
        self.g.read=lambda s,r,o,p,endpoint=None: (None,{'etag':'etag-a'}) if o=='head_object' else read(s,r,o,p,endpoint)
        self.assertEqual(self.h.inspect(self.g,node,{'child'}).status,'unresolved')

    def test_missing_or_wrong_response_version_and_404_never_confirm_delete(self):
        node=self.add_object();obs=self.h.inspect(self.g,node,{'child'});self.g.write_headers={}
        result=self.h.submit(self.g,node,obs,'attempt')
        self.assertEqual(result.status,'unresolved');self.assertIsNone(result.operation_evidence)
        self.assertEqual(self.h.inspect(self.g,node,{'child'}).status,'unresolved')

    def test_replication_any_relationship_blocks_entire_object_branch(self):
        for op,value in [('list_replication_policies',[{'id':'policy','destination_bucket_name':'outside','destination_region_name':R}]),('list_replication_policies',[{}]),('list_replication_sources',[{'source_bucket_name':'outside','source_region_name':R,'policy_name':'p'}])]:
            with self.subTest(op=op):
                self.setUp();self.g.inventory[op]=value;self.g.inventory['list_objects']=[obj()]
                nodes,_,_=self.discover();node=next(n for n in nodes if n.resource_type=='ObjectStorageObject')
                self.assertTrue(node.blockers);self.assertEqual(self.h.inspect(self.g,node,{'child'}).status,'unresolved')
                self.assertFalse(self.writes())

    def test_readonly_or_unknown_replication_flags_block(self):
        for field,value in [('is_read_only',True),('replication_enabled',True),('is_read_only',None)]:
            self.setUp();node=self.add_object();self.g.bucket[field]=value
            self.assertEqual(self.h.inspect(self.g,node,{'child'}).status,'unresolved')

    def rule(self,locked=None):
        return {'id':'rule','etag':'retention-etag','time_created':'2026-10-01T00:00:00+00:00','time_modified':'2026-10-01T00:00:00+00:00','time_rule_locked':locked,'duration':None}

    def test_unlocked_retention_preparation_is_pending_for_propagation(self):
        self.g.inventory['list_retention_rules']=[self.rule()];self.g.inventory['list_objects']=[obj()]
        nodes,edges,_=self.discover();rule=next(n for n in nodes if n.resource_type=='ObjectStorageRetentionRule');object_node=next(n for n in nodes if n.resource_type=='ObjectStorageObject')
        self.assertEqual(rule.action,'prepare');self.assertIn((rule.key,object_node.key),[(e.before,e.after) for e in edges])
        result=self.h.submit(self.g,rule,self.h.inspect(self.g,rule,{'child'}),'attempt')
        self.assertEqual(result.status,'pending')
        self.assertEqual(self.h.reconcile_submission(self.g,rule,result.operation_evidence,{'child'}).status,'pending')
        self.g.advance(self.g.now+timedelta(seconds=31))
        self.assertEqual(self.h.reconcile_submission(self.g,rule,result.operation_evidence,{'child'}).status,'deleted')

    def test_locked_and_malformed_lock_times_have_no_guessed_schedule(self):
        for locked in ['2026-10-07T00:00:00+00:00','invalid','2026-10-07T00:00:00']:
            self.setUp();self.g.inventory['list_retention_rules']=[self.rule(locked)];node=self.add_object()
            self.assertTrue(node.blockers)
            obs=self.h.inspect(self.g,node,{'child'});self.assertEqual(obs.status,'unresolved');self.assertIsNone(obs.scheduled_at)

    def test_future_lock_is_deletable_before_deadline_but_drift_blocks(self):
        self.g.inventory['list_retention_rules']=[self.rule('2026-10-09T00:00:00+00:00')]
        node=self.node('ObjectStorageRetentionRule');self.assertEqual(node.action,'prepare')
        self.g.advance(self.g.now+timedelta(days=2))
        self.assertEqual(self.h.inspect(self.g,node,{'child'}).status,'unresolved')

    def test_lifecycle_preparation_and_par_are_explicit_before_bucket(self):
        self.g.bucket['object_lifecycle_policy_etag']='policy-etag';self.g.inventory['list_objects']=[obj()]
        self.g.inventory['list_preauthenticated_requests']=[{'id':'par','name':'p','access_type':'ObjectRead','time_created':'2026-10-01T00:00:00+00:00','access_uri':'SECRET'}]
        nodes,edges,_=self.discover();policy=next(n for n in nodes if n.resource_type=='ObjectStorageLifecyclePolicy');par=next(n for n in nodes if n.resource_type=='ObjectStoragePAR')
        object_node=next(n for n in nodes if n.resource_type=='ObjectStorageObject')
        self.assertIn((policy.key,object_node.key),[(e.before,e.after) for e in edges])
        self.assertNotIn('SECRET',str(nodes));self.assertEqual(self.h.inspect(self.g,object_node,{'child'}).status,'unresolved')
        self.h.submit(self.g,policy,self.h.inspect(self.g,policy,{'child'}),'attempt')
        self.assertEqual(self.writes()[-1][4]['if_match'],'policy-etag')
        self.h.submit(self.g,par,self.h.inspect(self.g,par,{'child'}),'attempt')
        self.assertEqual(self.writes()[-1][3],'delete_preauthenticated_request')
        self.assertEqual(self.h.inspect(self.g,object_node,{'child'}).status,'present')

    def test_upload_abort_exact_identity_and_bucket_empty_condition(self):
        self.g.inventory['list_multipart_uploads']=[{'object':'a','upload_id':'upload','time_created':'2026-10-02T00:00:00+00:00','namespace':'canonical','bucket':'bucket'}]
        nodes,_,_=self.discover();upload=next(n for n in nodes if n.resource_type=='ObjectStorageMultipartUpload');bucket=next(n for n in nodes if n.resource_type=='Bucket')
        self.assertEqual(self.h.inspect(self.g,bucket,{'child'}).status,'unresolved')
        self.h.submit(self.g,upload,self.h.inspect(self.g,upload,{'child'}),'attempt')
        self.assertEqual(self.writes()[-1][4],{'namespace_name':'canonical','bucket_name':'bucket','object_name':'a','upload_id':'upload','opc_client_request_id':'attempt'})
        result=self.h.submit(self.g,bucket,self.h.inspect(self.g,bucket,{'child'}),'attempt')
        self.assertEqual(result.status,'pending');self.assertEqual(result.operation_evidence['http_status'],204)

    def test_batch_disabled_unique_names_uses_real_sdk_wire_model(self):
        self.g.inventory['list_objects']=[obj('a'),obj('b')]
        nodes=[n for n in self.discover()[0] if n.resource_type=='ObjectStorageObject']
        self.assertTrue(self.h.batch_group(self.g,nodes,{'child'}))
        results=self.h.submit_group(self.g,nodes,{'child'},'attempt')
        details=self.writes()[-1][4]['batch_delete_objects_details']
        client=object.__new__(oci.base_client.BaseClient)
        client.complex_type_mappings=oci.object_storage.models.object_storage_type_mapping
        wire=client.sanitize_for_serialization(details)
        self.assertEqual(wire,{'objects':[{'objectName':'a','ifMatch':'etag-a'},{'objectName':'b','ifMatch':'etag-b'}],'isSkipDeletedResult':False})
        self.assertEqual(set(results),{n.key for n in nodes})
        self.assertTrue(all(r.operation_evidence for r in results.values()))
        self.assertFalse(self.g.inventory['list_objects'])

    def test_batch_suspended_history_mixed_bucket_and_duplicate_names_excluded(self):
        node=self.add_object()
        for value in ['Suspended','Enabled']:
            self.g.bucket['versioning']=value;self.assertIsNone(self.h.batch_group(self.g,[node],{'child'}))
        self.g.bucket['versioning']='Disabled';self.g.inventory['list_object_versions']=[obj(version='retained')]
        self.assertIsNone(self.h.batch_group(self.g,[node],{'child'}))
        self.g.inventory['list_object_versions']=[]
        self.assertIsNone(self.h.batch_group(self.g,[node,node],{'child'}))

    def test_batch_partial_missing_conflicting_result_never_success(self):
        node=self.add_object();write=self.g.write
        for payload in [{'deleted':[],'failed':[]},{'deleted':[{'object_name':'a','time_last_modified':'2026-10-08T00:00:00+00:00'}],'failed':[{'object_name':'a','status_code':409}]},{'deleted':[{'object_name':'other','time_last_modified':'2026-10-08T00:00:00+00:00'}],'failed':[]}]:
            self.g.write=lambda *args: (payload,{'__http_status__':200})
            results=self.h.submit_group(self.g,[node],{'child'},'attempt')
            self.assertEqual(results[node.key].status,'unresolved')
        self.g.write=write

    def test_gateway_preserves_real_status_and_registers_explicit_operations(self):
        class Client:
            def head_object(self,**kwargs):return SimpleNamespace(data=None,headers={'ETag':'e','Version-Id':'v'},status=200)
            def delete_object(self,**kwargs):return SimpleNamespace(data=None,headers={'Version-Id':'v'},status=204)
        gateway=Gateway({'tenancy':'t','region':R});gateway._clients[('object_storage',R,None)]=Client()
        _,headers=gateway.read('object_storage',R,'head_object',{'namespace_name':'canonical','bucket_name':'bucket','object_name':'a','version_id':'v'})
        self.assertEqual(headers['__http_status__'],200)
        _,headers=gateway.write('object_storage',R,'delete_object',{'namespace_name':'canonical','bucket_name':'bucket','object_name':'a','version_id':'v'})
        self.assertEqual(headers['__http_status__'],204);self.assertEqual(headers['version-id'],'v')

    def test_missing_bound_parent_and_new_handler_require_explicit_binding(self):
        node=self.add_object();parent=self.node('Bucket')
        handler=storage.Storage(now=lambda:self.g.now)
        self.assertEqual(handler.inspect(self.g,node,{'child'}).status,'unresolved')
        handler.bind_plan([parent,node])
        self.assertEqual(handler.inspect(self.g,node,{'child'}).status,'present')

    def test_version_identity_key_has_unambiguous_name_and_version_components(self):
        self.g.bucket['versioning']='Enabled'
        self.g.inventory['list_object_versions']=[obj('a\x00b',version='c'),obj('a',version='b\x00c')]
        nodes,_,probes=self.discover()
        self.assertEqual(sum(n.resource_type=='ObjectStorageVersion' for n in nodes),2)
        self.assertTrue(all(p.status=='complete' for p in probes))

    def test_locked_retention_does_not_protect_uncommitted_upload(self):
        self.g.inventory['list_retention_rules']=[self.rule('2026-10-07T00:00:00+00:00')]
        self.g.inventory['list_multipart_uploads']=[{'object':'a','upload_id':'upload','time_created':'2026-10-02T00:00:00+00:00','namespace':'canonical','bucket':'bucket'}]
        upload=self.node('ObjectStorageMultipartUpload')
        self.assertFalse(upload.blockers)
        self.assertEqual(self.h.inspect(self.g,upload,{'child'}).status,'present')

    def test_bucket_conditional_204_and_complete_fresh_list_is_positive_proof(self):
        node=self.node('Bucket');result=self.h.submit(self.g,node,self.h.inspect(self.g,node,{'child'}),'attempt')
        self.assertEqual(self.h.reconcile_submission(self.g,node,result.operation_evidence,{'child'}).status,'deleted')
        self.assertEqual(self.writes()[-1][4]['if_match'],'bucket-etag')

    def test_head_exact_version_conflicting_identity_blocks(self):
        self.g.bucket['versioning']='Enabled';self.g.inventory['list_object_versions']=[obj(version='v1')]
        node=self.node('ObjectStorageVersion');read=self.g.read
        self.g.read=lambda s,r,o,p,endpoint=None: (None,{'etag':'etag-v1','version-id':'other','__http_status__':200}) if o=='head_object' else read(s,r,o,p,endpoint)
        self.assertEqual(self.h.inspect(self.g,node,{'child'}).status,'unresolved')

    def test_lost_write_response_is_never_replayed_by_reconciliation(self):
        node=self.add_object();obs=self.h.inspect(self.g,node,{'child'});write=self.g.write
        def lost(*args):
            write(*args);raise TimeoutError('response lost')
        self.g.write=lost
        with self.assertRaises(TimeoutError):self.h.submit(self.g,node,obs,'attempt')
        self.assertFalse(self.g.inventory['list_objects'])
        self.assertEqual(self.h.reconcile_submission(self.g,node,None,{'child'}).status,'unresolved')
        self.assertEqual(len(self.writes()),1)

    def test_batch_completed_item_does_not_hide_new_version_or_enabled_race(self):
        node=self.add_object();result=self.h.submit_group(self.g,[node],{'child'},'attempt')[node.key]
        self.g.bucket['versioning']='Enabled';self.g.inventory['list_object_versions']=[obj(version='new')]
        self.assertEqual(self.h.reconcile_submission(self.g,node,result.operation_evidence,{'child'}).status,'unresolved')

    def test_batch_valid_partial_success_preserves_good_item_and_failed_item(self):
        self.g.inventory['list_objects']=[obj('a'),obj('b')]
        nodes=[n for n in self.discover()[0] if n.resource_type=='ObjectStorageObject']
        self.g.write=lambda *args: ({'deleted':[{'object_name':'a','time_last_modified':'2026-10-08T00:00:00+00:00'}],
                                  'failed':[{'object_name':'b','status_code':409,'error_message':'private error'}]}, {})
        results=self.h.submit_group(self.g,nodes,{'child'},'attempt')
        a=next(n for n in nodes if n.metadata['object_name']=='a');b=next(n for n in nodes if n.metadata['object_name']=='b')
        self.assertIsNotNone(results[a.key].operation_evidence);self.assertEqual(results[b.key].status,'unresolved')
        self.assertNotIn('private error',str(results))

    def test_object_inventory_requests_service_identity_fields(self):
        node=self.add_object()
        events=[e for e in self.g.events if e[3]=='list_objects']
        self.assertEqual(events[0][4]['fields'],'name,etag,timeCreated,timeModified')

    def test_bucket_evidence_cannot_hide_recreation_failed_inventory_or_wrong_operation(self):
        node=self.node('Bucket');result=self.h.submit(self.g,node,self.h.inspect(self.g,node,{'child'}),'attempt')
        evidence=result.operation_evidence
        for bad in [None,dict(evidence,operation='delete_object'),dict(evidence,http_status=200),dict(evidence,etag=None)]:
            self.assertEqual(self.h.reconcile_submission(self.g,node,bad,{'child'}).status,'unresolved')
        self.g.bucket={'id':'new','name':'bucket','namespace':'canonical','compartment_id':'child','time_created':'2026-10-08T00:00:00+00:00','etag':'new','versioning':'Disabled'}
        self.assertEqual(self.h.reconcile_submission(self.g,node,evidence,{'child'}).status,'unresolved')
        self.g.bucket=None;self.g.deny('object_storage',R,'list_buckets')
        self.assertEqual(self.h.reconcile_submission(self.g,node,evidence,{'child'}).status,'unresolved')

    def test_exact_version_response_header_mismatch_remains_unresolved(self):
        self.g.bucket['versioning']='Enabled';self.g.inventory['list_object_versions']=[obj(version='v1')]
        node=self.node('ObjectStorageVersion');obs=self.h.inspect(self.g,node,{'child'})
        write=self.g.write
        def wrong(*args):
            data,headers=write(*args);headers['version-id']='wrong';return data,headers
        self.g.write=wrong
        result=self.h.submit(self.g,node,obs,'attempt')
        self.assertEqual(result.status,'unresolved');self.assertIsNone(result.operation_evidence)

    def test_sdk_generated_methods_accept_handler_kwargs_and_preserve_wire_identity(self):
        # Exercise installed generated SDK methods up to their HTTP transport.
        # No signer, socket, credentials, or live mutation is involved.
        calls=[]
        class Transport:
            def get_preferred_retry_strategy(self,**kwargs):return oci.retry.NoneRetryStrategy()
            def call_api(self,**kwargs):
                calls.append(kwargs);return SimpleNamespace(data=None,headers={},status=204)
        client=object.__new__(oci.object_storage.ObjectStorageClient)
        client.base_client=Transport();client.retry_strategy=None
        gateway=Gateway({'tenancy':'t','region':R});gateway._clients[('object_storage',R,None)]=client
        base={'namespace_name':'canonical','bucket_name':'bucket'}
        contracts=[('head_object','read',dict(object_name='a',version_id='v')),
            ('delete_object','write',dict(object_name='a',version_id='v',if_match='e',opc_client_request_id='attempt')),
            ('abort_multipart_upload','write',dict(object_name='a',upload_id='u',opc_client_request_id='attempt')),
            ('delete_bucket','write',dict(if_match='e',opc_client_request_id='attempt')),
            ('delete_preauthenticated_request','write',dict(par_id='p',opc_client_request_id='attempt')),
            ('delete_object_lifecycle_policy','write',dict(if_match='policy',opc_client_request_id='attempt')),
            ('get_retention_rule','read',dict(retention_rule_id='r')),
            ('delete_retention_rule','write',dict(retention_rule_id='r',if_match='e',opc_client_request_id='attempt')),
            ('list_preauthenticated_requests','read',{}),('get_object_lifecycle_policy','read',{}),
            ('list_replication_sources','read',{}),('list_objects','read',dict(fields='name,etag,timeCreated,timeModified')),
            ('batch_delete_objects','write',dict(batch_delete_objects_details=oci.object_storage.models.BatchDeleteObjectsDetails(
                objects=[oci.object_storage.models.BatchDeleteObjectIdentifier(object_name='a',if_match='e')],is_skip_deleted_result=False),opc_client_request_id='attempt'))]
        for operation,mode,extra in contracts:
            with self.subTest(operation=operation):
                if mode=='read':gateway.read('object_storage',R,operation,dict(base,**extra))
                else:gateway.write('object_storage',R,operation,dict(base,**extra))
                self.assertEqual(calls[-1]['operation_name'],operation)
                self.assertEqual(calls[-1]['path_params']['namespaceName'],'canonical')
                self.assertEqual(calls[-1]['path_params']['bucketName'],'bucket')
        delete_call=next(c for c in calls if c['operation_name']=='delete_object')
        self.assertEqual(delete_call['query_params']['versionId'],'v')
        self.assertEqual(delete_call['header_params']['if-match'],'e')
        abort_call=next(c for c in calls if c['operation_name']=='abort_multipart_upload')
        self.assertNotIn('if-match',abort_call['header_params'])

    def test_saved_inventory_forged_child_key_cannot_create_absence_proof(self):
        node=self.add_object();parent=self.node('Bucket')
        snapshot=deepcopy(parent.metadata['inventory_snapshot'])
        snapshot['forged-key']=snapshot[node.key]
        forged=replace(node,key='forged-key')
        self.h.bind_plan([replace(parent,metadata=dict(parent.metadata,inventory_snapshot=snapshot)),forged])
        evidence={'node_key':'forged-key','bucket_id':node.metadata['bucket_id'],'bucket_created':node.metadata['bucket_created'],
            'region':R,'operation':'delete_object','http_status':204,'etag':'etag-a','submitted_at':self.g.now.isoformat()}
        self.assertEqual(self.h.reconcile_submission(self.g,forged,evidence,{'child'}).status,'unresolved')

    def par(self,access_type):
        return {'id':'par','name':'p','object_name':'a','access_type':access_type,
                'time_created':'2026-10-01T00:00:00+00:00','time_expires':'2026-10-09T00:00:00+00:00'}

    def test_write_capable_par_is_preparation_before_objects_and_versions(self):
        for access in ['ObjectWrite','ObjectReadWrite','AnyObjectWrite','AnyObjectReadWrite']:
            for versioned in [False,True]:
                with self.subTest(access=access,versioned=versioned):
                    self.setUp();self.g.inventory['list_preauthenticated_requests']=[self.par(access)]
                    self.g.inventory['list_object_versions' if versioned else 'list_objects']=[obj(version='v') if versioned else obj()]
                    if versioned:self.g.bucket['versioning']='Enabled'
                    nodes,edges,_=self.discover()
                    par=next(n for n in nodes if n.resource_type=='ObjectStoragePAR')
                    target=next(n for n in nodes if n.resource_type in ('ObjectStorageObject','ObjectStorageVersion'))
                    self.assertEqual(par.action,'prepare')
                    self.assertEqual(self.h.classify(replace(par,action='delete')).action,'prepare')
                    self.assertIn((par.key,target.key),[(e.before,e.after) for e in edges])
                    observation=self.h.inspect(self.g,target,{'child'})
                    self.assertEqual(observation.status,'unresolved')
                    with self.assertRaises(CleanupError):self.h.submit(self.g,target,observation,'attempt')
                    result=self.h.submit(self.g,par,self.h.inspect(self.g,par,{'child'}),'attempt')
                    self.assertEqual(self.h.reconcile_submission(self.g,par,result.operation_evidence,{'child'}).status,'deleted')
                    self.assertEqual(self.h.inspect(self.g,target,{'child'}).status,'present')

    def test_batch_waits_for_write_par_preparation_and_rechecks_live_producers(self):
        self.g.inventory['list_objects']=[obj()]
        self.g.inventory['list_preauthenticated_requests']=[self.par('AnyObjectWrite')]
        nodes,_,_=self.discover();target=next(n for n in nodes if n.resource_type=='ObjectStorageObject')
        par=next(n for n in nodes if n.resource_type=='ObjectStoragePAR')
        self.assertIsNone(self.h.batch_group(self.g,[target],{'child'}))
        with self.assertRaises(CleanupError):self.h.submit_group(self.g,[target],{'child'},'attempt')
        self.assertFalse(self.writes())
        self.h.submit(self.g,par,self.h.inspect(self.g,par,{'child'}),'attempt')
        self.assertIsNotNone(self.h.batch_group(self.g,[target],{'child'}))
        self.g.inventory['list_preauthenticated_requests']=[self.par('AnyObjectWrite')]
        with self.assertRaises(CleanupError):self.h.submit_group(self.g,[target],{'child'},'attempt')
        self.assertEqual(len(self.writes()),1)

    def test_unknown_par_permission_is_unresolved_for_individual_and_batch(self):
        for access in [None,'UNKNOWN_ENUM_VALUE','BucketWrite','objectwrite',[],{}]:
            with self.subTest(access=access):
                self.setUp();self.g.inventory['list_preauthenticated_requests']=[self.par(access)]
                self.g.inventory['list_objects']=[obj()]
                nodes,_,_=self.discover()
                self.assertTrue(any(n.resource_type=='ObjectStoragePAR' for n in nodes))
                target=next(n for n in nodes if n.resource_type=='ObjectStorageObject')
                par=next(n for n in nodes if n.resource_type=='ObjectStoragePAR')
                self.assertTrue(par.blockers);self.assertEqual(par.action,'unresolved')
                self.assertEqual(self.h.classify(par).action,'unresolved')
                self.assertEqual(self.h.inspect(self.g,target,{'child'}).status,'unresolved')
                self.assertIsNone(self.h.batch_group(self.g,[target],{'child'}));self.assertFalse(self.writes())

    def test_read_only_par_waits_only_before_bucket_and_allows_objects_and_batch(self):
        for access in ['ObjectRead','AnyObjectRead']:
            with self.subTest(access=access):
                self.setUp();self.g.inventory['list_preauthenticated_requests']=[self.par(access)]
                self.g.inventory['list_objects']=[obj()]
                nodes,edges,_=self.discover();target=next(n for n in nodes if n.resource_type=='ObjectStorageObject')
                par=next(n for n in nodes if n.resource_type=='ObjectStoragePAR');bucket=next(n for n in nodes if n.resource_type=='Bucket')
                self.assertEqual(par.action,'delete');self.assertNotIn((par.key,target.key),[(e.before,e.after) for e in edges])
                self.assertIn((par.key,bucket.key),[(e.before,e.after) for e in edges])
                self.assertEqual(self.h.inspect(self.g,target,{'child'}).status,'present')
                self.assertIsNotNone(self.h.batch_group(self.g,[target],{'child'}))

    def test_actual_sdk_par_access_enums_cover_the_producer_allowlist(self):
        cls=oci.object_storage.models.PreauthenticatedRequestSummary
        self.assertEqual({getattr(cls,name) for name in dir(cls) if name.startswith('ACCESS_TYPE_')},
                         {'ObjectRead','ObjectWrite','ObjectReadWrite','AnyObjectRead','AnyObjectWrite','AnyObjectReadWrite'})
