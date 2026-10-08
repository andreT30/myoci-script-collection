"""Exact bucket-owned cleanup, with conservative retention/replication boundaries.

Task 9 calls bind_plan once after classifying the saved nodes, journals intent
before submit, persists Submission.operation_evidence immediately, and reconciles
that evidence through reconcile_submission. Absence by itself is never proof.
Task 8 may group same-depth ready nodes through batch_group/submit_group; the
server batch API is distinct from IAM bulk actions. Tracing IDs are not work IDs.
"""
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import oci

from .base import Handler
from ..model import CleanupError, Edge, Node, Observation, Probe, Submission, child_key

S='object_storage'
# SDK PreauthenticatedRequestSummary access_type values, verified at the SDK floor.
_PAR_WRITE=frozenset({'ObjectWrite','ObjectReadWrite','AnyObjectWrite','AnyObjectReadWrite'})
_PAR_READ=frozenset({'ObjectRead','AnyObjectRead'})
_TYPES=('Bucket','ObjectStorageObject','ObjectStorageVersion','ObjectStorageMultipartUpload',
        'ObjectStoragePAR','ObjectStorageLifecyclePolicy','ObjectStorageRetentionRule','ObjectStorageReplication')
_META=('bucket_id','bucket_name','namespace','bucket_created','inventory_snapshot','versioning',
       'identity','object_name','version_id','upload_id','par_id','retention_rule_id','policy_etag')
_LISTS=('list_objects','list_object_versions','list_multipart_uploads',
        'list_preauthenticated_requests','list_retention_rules','list_replication_policies','list_replication_sources')


def _par_access(identity):
    access=identity.get('access_type') if isinstance(identity,dict) else None
    return access if isinstance(access,str) else None


def _text(value):
    if not isinstance(value,str) or not value:raise CleanupError('Missing typed storage identity')
    return value


def _time(value):
    _text(value)
    result=datetime.fromisoformat(value.replace('Z','+00:00'))
    if result.tzinfo is None or result.utcoffset()!=timedelta(0):raise CleanupError('Unknown UTC storage timestamp')
    return result


def _scope(gateway):
    return set(getattr(gateway,'cleanup_scope',set(getattr(gateway,'compartment_links',{}))))


def _blocked(node,detail):
    return replace(node,action='unresolved',blockers=tuple(sorted(set(node.blockers+(detail,)))))


class Storage(Handler):
    name='storage';action='delete';resource_types=_TYPES;metadata_keys=_META

    def __init__(self,now=None):
        self.now=now or (lambda:datetime.now(timezone.utc))
        self._snapshots={}

    def classify(self,node):
        action='prepare' if node.resource_type in ('ObjectStorageLifecyclePolicy','ObjectStorageRetentionRule') else 'delete'
        if node.resource_type=='ObjectStoragePAR':
            access=_par_access(node.metadata.get('identity'))
            if access in _PAR_WRITE:action='prepare'
            elif access not in _PAR_READ:
                node=_blocked(node,'Unknown PAR access permission; producer safety unresolved')
        if node.resource_type=='ObjectStorageReplication' or node.blockers:action='unresolved'
        return replace(node,handler=self.name,action=action,
                       metadata={k:v for k,v in node.metadata.items() if k in self.metadata_keys})

    def bind_plan(self,nodes):
        """Load the saved parent inventory once, never expand it during execution."""
        self._snapshots={(n.region,n.key):n for n in nodes if n.resource_type=='Bucket'}

    def _namespace(self,gateway,region):
        value,_=gateway.read(S,region,'get_namespace',{})
        return _text(value)

    def _bucket(self,gateway,region,namespace,name):
        row,headers=gateway.read(S,region,'get_bucket',{'namespace_name':namespace,'bucket_name':name})
        if not isinstance(row,dict):raise CleanupError('Unknown bucket response')
        _text(row.get('id'));_time(row.get('time_created'));_text(row.get('compartment_id'))
        if row.get('namespace')!=namespace or row.get('name')!=name:raise CleanupError('Canonical bucket path mismatch')
        if row.get('versioning') not in ('Disabled','Enabled','Suspended'):raise CleanupError('Unknown bucket versioning')
        return row,headers

    def _inventory(self,gateway,region,row):
        """Only identifiers and safe metadata survive; no object bytes or PAR URLs."""
        params={'namespace_name':row['namespace'],'bucket_name':row['name']}
        values={op:gateway.items(S,region,op,dict(params,fields='name,etag,timeCreated,timeModified') if op=='list_objects' else params) for op in _LISTS}
        inventory={};issues=[]
        def add(kind,path,identity,extra=None,version=''):
            key=child_key(S+'/'+kind,region,row['id'],path,version)
            if key in inventory:raise CleanupError('Duplicate storage child identity')
            inventory[key]={'resource_type':kind,'identity':identity,**(extra or {})}
        version_names=set()
        for item in values['list_object_versions']:
            name=_text(item.get('name'));version=_text(item.get('version_id'))
            if type(item.get('is_delete_marker')) is not bool:raise CleanupError('Unknown version marker state')
            identity={k:item.get(k) for k in ('name','version_id','etag','time_created','time_modified','is_delete_marker')}
            _time(identity['time_created']);_text(identity['etag'])
            add('ObjectStorageVersion',name,identity,{'object_name':name,'version_id':version},version)
            version_names.add(name)
        for item in values['list_objects']:
            name=_text(item.get('name'))
            if name in version_names:continue
            identity={k:item.get(k) for k in ('name','etag','time_created','time_modified')}
            _time(identity['time_created']);_text(identity['etag'])
            add('ObjectStorageObject',name,identity,{'object_name':name})
            if row['versioning']!='Disabled':issues.append('Object lacks exact retained version identity')
        for item in values['list_multipart_uploads']:
            name=_text(item.get('object'));upload=_text(item.get('upload_id'));_time(item.get('time_created'))
            if item.get('namespace')!=row['namespace'] or item.get('bucket')!=row['name']:raise CleanupError('Upload parent mismatch')
            identity={k:item.get(k) for k in ('object','upload_id','time_created','namespace','bucket')}
            add('ObjectStorageMultipartUpload',name,identity,{'object_name':name,'upload_id':upload},upload)
        for item in values['list_preauthenticated_requests']:
            key=_text(item.get('id'));_time(item.get('time_created'))
            identity={k:item.get(k) for k in ('id','time_created','name','object_name','access_type','time_expires')}
            add('ObjectStoragePAR',key,identity,{'par_id':key})
            if _par_access(identity) not in _PAR_WRITE|_PAR_READ:
                issues.append('Unknown PAR access permission; producer safety unresolved')
        for item in values['list_retention_rules']:
            key=_text(item.get('id'));_time(item.get('time_created'));_text(item.get('etag'))
            identity={k:item.get(k) for k in ('id','etag','time_created','time_modified','time_rule_locked','duration')}
            add('ObjectStorageRetentionRule',key,identity,{'retention_rule_id':key})
            lock=identity['time_rule_locked']
            try:
                if lock is not None and self.now()>=_time(lock):issues.append('Locked retention rule; eligibility requires service proof')
                duration=identity['duration']
                if duration is not None and (not isinstance(duration,dict) or type(duration.get('time_amount')) is not int
                    or duration['time_amount']<=0 or duration.get('time_unit') not in ('DAYS','YEARS')):
                    raise CleanupError('Unknown retention duration')
            except Exception:issues.append('Malformed retention timing; no deletion schedule inferred')
        if row.get('object_lifecycle_policy_etag'):
            policy,headers=gateway.read(S,region,'get_object_lifecycle_policy',params)
            etag=_text(headers.get('etag'))
            if etag!=row['object_lifecycle_policy_etag'] or not isinstance(policy,dict) or not isinstance(policy.get('items'),list):
                raise CleanupError('Lifecycle policy identity changed')
            # Rules contain only producer configuration; retain service fields needed
            # to detect drift without saving arbitrary configuration payloads.
            rules=[]
            for rule in policy['items']:
                if not isinstance(rule,dict):raise CleanupError('Unknown lifecycle rule')
                rules.append({k:rule.get(k) for k in ('name','action','is_enabled','time_amount','time_unit','target','object_name_filter')})
            add('ObjectStorageLifecyclePolicy','policy',{'etag':etag,'rules':rules},{'policy_etag':etag})
        replication=values['list_replication_policies']+values['list_replication_sources']
        if row.get('replication_enabled') is not False or row.get('is_read_only') is not False or replication:
            issues.append('Replication or read-only relationship lacks verified stop and scope proof')
            # Every known configuration is explicitly mapped, including malformed
            # summaries. No endpoint or operation is taken from this metadata.
            for i,item in enumerate(replication or [{}]):
                safe={k:item.get(k) for k in ('id','name','destination_region_name','destination_bucket_name',
                     'source_region_name','source_bucket_name','policy_name','status','time_created')}
                add('ObjectStorageReplication',str(i),safe)
        return inventory,sorted(set(issues))

    def _nodes(self,row,region,inventory,issues):
        meta={'bucket_id':row['id'],'bucket_name':row['name'],'namespace':row['namespace'],
              'bucket_created':row['time_created'],'versioning':row['versioning']}
        parent=Node(row['id'],'Bucket',region,row['compartment_id'],row['name'],'',self.name,'delete',dict(meta,inventory_snapshot=inventory))
        children=[]
        for key,entry in inventory.items():
            kind=entry['resource_type'];metadata=dict(meta,**{k:v for k,v in entry.items() if k!='resource_type'})
            node=Node(key,kind,region,row['compartment_id'],metadata.get('object_name') or kind,'',self.name,
                'prepare' if kind in ('ObjectStorageLifecyclePolicy','ObjectStorageRetentionRule') else 'delete',metadata)
            node=self.classify(node)
            if kind=='ObjectStorageReplication':node=_blocked(node,'Replication detachment completion contract unresolved')
            if issues:
                for issue in issues:
                    if kind=='ObjectStorageMultipartUpload' and ('retention' in issue.lower()):continue
                    node=_blocked(node,issue)
            children.append(node)
        for issue in issues:parent=_blocked(parent,issue)
        edges=[Edge(n.key,parent.key,'Bucket-owned child must complete before bucket deletion') for n in children]
        preparations=[n for n in children if n.action=='prepare']
        for prep in preparations:
            for target in children:
                if target.resource_type in ('ObjectStorageObject','ObjectStorageVersion'):
                    edges.append(Edge(prep.key,target.key,'Remove writable PAR, lifecycle or unlocked retention before object mutations'))
        return parent,children,edges

    def discover(self,gateway,compartment_id,region):
        nodes=[];edges=[];probes=[]
        try:
            namespace=self._namespace(gateway,region)
            summaries=gateway.items(S,region,'list_buckets',{'namespace_name':namespace,'compartment_id':compartment_id})
            names=set()
            for summary in summaries:
                name=_text(summary.get('name'))
                if name in names:raise CleanupError('Duplicate bucket name')
                names.add(name)
                row,_=self._bucket(gateway,region,namespace,name)
                if row['compartment_id']!=compartment_id:raise CleanupError('Bucket owner changed')
                try:
                    inventory,issues=self._inventory(gateway,region,row)
                    parent,children,links=self._nodes(row,region,inventory,issues)
                    nodes.extend([parent]+children);edges.extend(links)
                    self._snapshots[(parent.region,parent.key)]=parent
                    probes.append(Probe(S,region,compartment_id,'complete','Exact bucket inventory: '+name))
                except Exception:
                    meta={'bucket_id':row['id'],'bucket_name':name,'namespace':namespace,'bucket_created':row['time_created'],'versioning':row['versioning']}
                    nodes.append(_blocked(Node(row['id'],'Bucket',region,compartment_id,name,'',self.name,'unresolved',meta),
                                          'Bucket child discovery failed; no partial deletion inventory'))
                    probes.append(Probe(S,region,compartment_id,'failed','Bucket child inventory failed: '+name))
            probes.append(Probe(S,region,compartment_id,'complete','Canonical namespace and complete bucket list'))
        except Exception:probes.append(Probe(S,region,compartment_id,'failed','Canonical namespace or bucket identity inventory failed'))
        return nodes,edges,probes

    def _fresh(self,gateway,node,scope):
        namespace=self._namespace(gateway,node.region)
        if namespace!=node.metadata.get('namespace'):raise CleanupError('Namespace changed')
        row,headers=self._bucket(gateway,node.region,namespace,_text(node.metadata.get('bucket_name')))
        if row['compartment_id']!=node.compartment_id or row['compartment_id'] not in scope:raise CleanupError('Bucket owner moved')
        if row['id']!=node.metadata.get('bucket_id') or row['time_created']!=node.metadata.get('bucket_created'):
            raise CleanupError('Bucket was recreated')
        saved=node if node.resource_type=='Bucket' else self._snapshots.get((node.region,row['id']))
        if saved is None or saved.region!=node.region or saved.compartment_id!=node.compartment_id:
            raise CleanupError('Saved bucket inventory is not bound')
        snapshot=saved.metadata.get('inventory_snapshot')
        if not isinstance(snapshot,dict):raise CleanupError('Missing complete saved inventory')
        inventory,issues=self._inventory(gateway,node.region,row)
        if node.resource_type=='ObjectStorageMultipartUpload':
            issues=[issue for issue in issues if 'retention' not in issue.lower()]
        if issues:raise CleanupError('Unsafe storage relationships or timing')
        for key,value in inventory.items():
            if snapshot.get(key)!=value:raise CleanupError('New or changed child requires report refresh')
        if row['versioning']!=saved.metadata.get('versioning'):raise CleanupError('Bucket versioning changed')
        if node.resource_type=='Bucket':
            if node.key!=row['id']:raise CleanupError('Bucket key mismatch')
        else:
            kind=node.resource_type
            if kind in ('ObjectStorageObject','ObjectStorageVersion','ObjectStorageMultipartUpload'):
                path=_text(node.metadata.get('object_name'))
                version=_text(node.metadata.get('version_id')) if kind=='ObjectStorageVersion' else _text(node.metadata.get('upload_id')) if kind=='ObjectStorageMultipartUpload' else ''
            elif kind=='ObjectStoragePAR':path=_text(node.metadata.get('par_id'));version=''
            elif kind=='ObjectStorageRetentionRule':path=_text(node.metadata.get('retention_rule_id'));version=''
            elif kind=='ObjectStorageLifecyclePolicy':path='policy';version=''
            else:raise CleanupError('Unsupported executable storage child')
            if node.key!=child_key(S+'/'+kind,node.region,row['id'],path,version):
                raise CleanupError('Saved child key does not match typed identity')
            entry=snapshot.get(node.key)
            expected={k:v for k,v in node.metadata.items() if k not in ('bucket_id','bucket_name','namespace','bucket_created','versioning')}
            if not entry or entry!={'resource_type':node.resource_type,**expected}:raise CleanupError('Child identity mismatch')
        return row,headers,inventory

    def inspect(self,gateway,node,scope):
        try:
            if node.blockers or node.resource_type not in _TYPES:raise CleanupError('Blocked storage target')
            row,headers,inventory=self._fresh(gateway,node,scope)
            params={'namespace_name':row['namespace'],'bucket_name':row['name']}
            if node.resource_type=='Bucket':
                if inventory:raise CleanupError('Bucket remains nonempty or configured')
                etag=_text(headers.get('etag'))
            else:
                entry=inventory.get(node.key)
                if entry is None:raise CleanupError('Absent child alone is ambiguous')
                kind=node.resource_type;identity=entry['identity'];etag=identity.get('etag')
                if kind in ('ObjectStorageObject','ObjectStorageVersion'):
                    if any(e['resource_type'] in ('ObjectStorageLifecyclePolicy','ObjectStorageRetentionRule') for e in inventory.values()):
                        raise CleanupError('Producer or retention preparation pending')
                    if any(e['resource_type']=='ObjectStoragePAR' and _par_access(e['identity']) in _PAR_WRITE
                           for e in inventory.values()):
                        raise CleanupError('Write-capable PAR producer preparation pending')
                    if kind=='ObjectStorageObject' and row['versioning']!='Disabled':raise CleanupError('Exact version required')
                    if kind=='ObjectStorageVersion' and identity['is_delete_marker']:
                        etag=_text(identity.get('etag'))
                    else:
                        args=dict(params,object_name=node.metadata['object_name'])
                        if kind=='ObjectStorageVersion':args['version_id']=node.metadata['version_id']
                        _,head=gateway.read(S,node.region,'head_object',args)
                        if head.get('__http_status__')!=200 or head.get('etag')!=identity['etag']:
                            raise CleanupError('HEAD identity is unresolved')
                        if kind=='ObjectStorageVersion' and head.get('version-id')!=node.metadata['version_id']:
                            raise CleanupError('HEAD version mismatch')
                        etag=_text(head.get('etag'))
                elif kind=='ObjectStorageRetentionRule':
                    rule,rule_headers=gateway.read(S,node.region,'get_retention_rule',dict(params,retention_rule_id=node.metadata['retention_rule_id']))
                    if {k:rule.get(k) for k in identity}!=identity:raise CleanupError('Retention identity changed')
                    lock=rule.get('time_rule_locked')
                    if lock is not None and self.now()>=_time(lock):raise CleanupError('Rule is now locked')
                    etag=_text(rule_headers.get('etag'))
                    if etag!=identity['etag']:raise CleanupError('Rule ETag changed')
                elif kind=='ObjectStorageReplication':raise CleanupError('Replication stop proof unresolved')
            return Observation('present',row['compartment_id'],'',None,etag,'Fresh immutable bucket and exact saved child verified')
        except Exception:return Observation('unresolved',node.compartment_id,'',None,None,'Storage identity, producer, scope or inventory unresolved; refresh report')

    def submit(self,gateway,node,observation,attempt_id):
        if node.blockers or observation.status!='present':raise CleanupError('Storage action is not ready')
        fresh=self.inspect(gateway,node,_scope(gateway))
        if fresh.status!='present' or fresh.etag!=observation.etag:raise CleanupError('Storage preflight changed')
        params={'namespace_name':node.metadata['namespace'],'bucket_name':node.metadata['bucket_name'],
                'opc_client_request_id':_text(attempt_id)}
        kind=node.resource_type
        if kind=='Bucket':operation='delete_bucket';params['if_match']=_text(fresh.etag)
        elif kind in ('ObjectStorageObject','ObjectStorageVersion'):
            operation='delete_object';params.update(object_name=node.metadata['object_name'],if_match=_text(fresh.etag))
            if kind=='ObjectStorageVersion':params['version_id']=node.metadata['version_id']
        elif kind=='ObjectStorageMultipartUpload':
            operation='abort_multipart_upload';params.update(object_name=node.metadata['object_name'],upload_id=node.metadata['upload_id'])
        elif kind=='ObjectStoragePAR':operation='delete_preauthenticated_request';params['par_id']=node.metadata['par_id']
        elif kind=='ObjectStorageLifecyclePolicy':operation='delete_object_lifecycle_policy';params['if_match']=_text(fresh.etag)
        elif kind=='ObjectStorageRetentionRule':operation='delete_retention_rule';params.update(retention_rule_id=node.metadata['retention_rule_id'],if_match=_text(fresh.etag))
        else:raise CleanupError('No storage mutation contract')
        _,headers=gateway.write(S,node.region,operation,params)
        if headers.get('__http_status__')!=204 or (kind=='ObjectStorageVersion' and headers.get('version-id')!=node.metadata['version_id']):
            return Submission('unresolved',None,None,'Response lacks exact completion evidence; reconcile without retry')
        evidence={'node_key':node.key,'bucket_id':node.metadata['bucket_id'],'bucket_created':node.metadata['bucket_created'],
                  'region':node.region,'operation':operation,'http_status':204,'etag':fresh.etag,
                  'submitted_at':self.now().isoformat()}
        if kind=='ObjectStorageVersion':evidence['version_id']=headers['version-id']
        return Submission('pending',None,None,'Operation completed; fresh full inventory reconciliation required',evidence)

    def reconcile_submission(self,gateway,node,evidence,scope):
        """Consume journaled positive completion evidence, then verify live absence.

        Evidence is journal data, never node metadata or SDK instructions. Bucket
        conditional DELETE204 establishes positive bucket operation completion;
        a fresh full bucket inventory corroborates absence. GET404 alone is
        never deletion proof. A recreated same-name bucket is explicit drift.
        """
        try:
            allowed={'node_key','bucket_id','bucket_created','region','operation','http_status','etag','submitted_at','version_id','deleted_at'}
            if not isinstance(evidence,dict) or set(evidence)-allowed:raise CleanupError('Malformed operation evidence')
            if (evidence.get('node_key')!=node.key or evidence.get('bucket_id')!=node.metadata['bucket_id']
                or evidence.get('bucket_created')!=node.metadata['bucket_created'] or evidence.get('region')!=node.region):
                raise CleanupError('Wrong operation evidence identity')
            expected={'Bucket':'delete_bucket','ObjectStorageObject':'delete_object','ObjectStorageVersion':'delete_object',
                'ObjectStorageMultipartUpload':'abort_multipart_upload','ObjectStoragePAR':'delete_preauthenticated_request',
                'ObjectStorageLifecyclePolicy':'delete_object_lifecycle_policy','ObjectStorageRetentionRule':'delete_retention_rule'}
            batch=evidence.get('operation')=='batch_delete_objects' and node.resource_type=='ObjectStorageObject'
            if not batch and (expected.get(node.resource_type)!=evidence.get('operation') or evidence.get('http_status')!=204):
                raise CleanupError('No exact terminal operation proof')
            if batch:_time(evidence.get('deleted_at'))
            submitted=_time(evidence.get('submitted_at'))
            if submitted>self.now():raise CleanupError('Future operation evidence')
            if node.resource_type=='ObjectStorageVersion' and evidence.get('version_id')!=node.metadata['version_id']:
                raise CleanupError('Wrong completed version')
            if node.resource_type in ('ObjectStorageObject','ObjectStorageVersion','ObjectStorageLifecyclePolicy','ObjectStorageRetentionRule'):
                if evidence.get('etag')!=node.metadata['identity'].get('etag'):raise CleanupError('Wrong submitted precondition')
            if node.resource_type=='Bucket':
                if node.compartment_id not in scope or node.key!=node.metadata['bucket_id']:
                    raise CleanupError('Bucket completion scope mismatch')
                _text(evidence.get('etag'))
                namespace=self._namespace(gateway,node.region)
                if namespace!=node.metadata['namespace']:raise CleanupError('Namespace changed')
                buckets=gateway.items(S,node.region,'list_buckets',{'namespace_name':namespace,'compartment_id':node.compartment_id})
                names=[_text(b.get('name')) for b in buckets]
                if len(names)!=len(set(names)):raise CleanupError('Duplicate bucket inventory')
                if node.metadata['bucket_name'] in names:
                    row,_=self._bucket(gateway,node.region,namespace,node.metadata['bucket_name'])
                    if row['id']!=node.key or row['time_created']!=node.metadata['bucket_created']:
                        raise CleanupError('Same-name bucket recreation requires refresh')
                    return Observation('pending',node.compartment_id,'',None,None,'Deleted bucket still appears in complete inventory')
                return Observation('deleted',node.compartment_id,'',None,None,'Conditional exact bucket DELETE204 and fresh complete inventory absence')
            _,_,inventory=self._fresh(gateway,node,scope)
            if node.key in inventory:return Observation('pending',node.compartment_id,'',None,None,'Child still appears in authoritative full inventory')
            if node.resource_type=='ObjectStorageRetentionRule' and self.now()<submitted+timedelta(seconds=30):
                return Observation('pending',node.compartment_id,'',None,None,'Retention deletion propagation interval remains pending')
            return Observation('deleted',node.compartment_id,'',None,None,'Exact operation completion and fresh complete inventory absence')
        except Exception:return Observation('unresolved',node.compartment_id,'',None,None,'Completion evidence or live inventory remains unresolved')

    def _batch_preflight(self,gateway,nodes,scope):
        """One complete live snapshot for one bounded group of saved identities."""
        if not nodes or len(nodes)>1000 or any(n.resource_type!='ObjectStorageObject' or n.blockers for n in nodes):
            raise CleanupError('Storage batch is ineligible')
        first=nodes[0]
        row,_,inventory=self._fresh(gateway,first,scope)
        if row['versioning']!='Disabled' or any(e['resource_type']=='ObjectStorageVersion' for e in inventory.values()):
            raise CleanupError('Exact version operations required')
        if any(e['resource_type'] in ('ObjectStorageLifecyclePolicy','ObjectStorageRetentionRule')
               or (e['resource_type']=='ObjectStoragePAR' and _par_access(e['identity']) in _PAR_WRITE)
               for e in inventory.values()):
            raise CleanupError('Producer or retention preparation pending')
        saved=self._snapshots[(first.region,row['id'])].metadata['inventory_snapshot']
        key=(first.region,first.compartment_id,row['namespace'],row['id'])
        names=set();identities=set()
        for node in nodes:
            if (node.region,node.compartment_id,node.metadata.get('namespace'),node.metadata.get('bucket_id'))!=key:
                raise CleanupError('Storage batch spans bucket identities')
            if node.metadata.get('bucket_name')!=row['name'] or node.metadata.get('bucket_created')!=row['time_created'] or node.metadata.get('versioning')!='Disabled':
                raise CleanupError('Storage batch saved bucket identity changed')
            name=_text(node.metadata.get('object_name'))
            if name in names or node.key in identities:raise CleanupError('Duplicate storage batch identity')
            names.add(name);identities.add(node.key)
            if node.key!=child_key(S+'/ObjectStorageObject',node.region,row['id'],name):
                raise CleanupError('Saved batch child key does not match typed identity')
            expected={k:v for k,v in node.metadata.items() if k not in ('bucket_id','bucket_name','namespace','bucket_created','versioning')}
            entry={'resource_type':'ObjectStorageObject',**expected}
            if saved.get(node.key)!=entry or inventory.get(node.key)!=entry:
                raise CleanupError('Saved batch child identity is absent or changed')
        return key,row,inventory

    def batch_group(self,gateway,nodes,scope):
        """Return a group key after one complete shared bucket preflight.

        Submission independently refreshes this snapshot and HEADs each object.
        Caller supplies dependency-ready nodes of one recomputed graph depth.
        """
        try:return self._batch_preflight(gateway,nodes,scope)[0]
        except Exception:return None

    def submit_group(self,gateway,nodes,scope,attempt_id,*,before_write=None):
        _,row,inventory=self._batch_preflight(gateway,nodes,scope)
        identifiers=[];observations={}
        for node in nodes:
            _,headers=gateway.read(S,node.region,'head_object',{
                'namespace_name':row['namespace'],'bucket_name':row['name'],'object_name':node.metadata['object_name']})
            etag=_text(headers.get('etag'))
            if headers.get('__http_status__')!=200 or etag!=inventory[node.key]['identity']['etag']:
                raise CleanupError('Batch HEAD identity is unresolved')
            observations[node.key]=Observation('present',node.compartment_id,'',None,etag,'Fresh exact object HEAD')
            identifiers.append(oci.object_storage.models.BatchDeleteObjectIdentifier(object_name=node.metadata['object_name'],if_match=etag))
        first=nodes[0]
        # A bucket can move, be recreated, or enable versioning during HEADs.
        # Recheck immediately before persisting the exact conditional body.
        namespace=self._namespace(gateway,first.region)
        if namespace!=row['namespace']:raise CleanupError('Canonical namespace changed during batch preflight')
        final,_=self._bucket(gateway,first.region,namespace,row['name'])
        if any(final[field]!=row[field] for field in ('id','compartment_id','time_created','namespace','name','versioning')) or final['versioning']!='Disabled':
            raise CleanupError('Bucket identity or versioning changed during batch preflight')
        params={
            'namespace_name':first.metadata['namespace'],'bucket_name':first.metadata['bucket_name'],
            'batch_delete_objects_details':oci.object_storage.models.BatchDeleteObjectsDetails(objects=identifiers,is_skip_deleted_result=False),
            'opc_client_request_id':_text(attempt_id)}
        if before_write is not None:before_write(params)
        data,_=gateway.write(S,first.region,'batch_delete_objects',params)
        results={n.key:Submission('unresolved',None,None,'Batch item completion is unresolved; reconcile without replay') for n in nodes}
        try:
            if not isinstance(data,dict) or not isinstance(data.get('deleted'),list) or not isinstance(data.get('failed'),list):return results
            names={n.metadata['object_name']:n for n in nodes};seen=set()
            for row in data['deleted']+data['failed']:
                name=row.get('object_name') if isinstance(row,dict) else None
                if name not in names or name in seen:return results
                seen.add(name)
            for row in data['deleted']:
                timestamp=_time(row.get('time_last_modified')).isoformat();node=names[row['object_name']]
                evidence={'node_key':node.key,'bucket_id':node.metadata['bucket_id'],'bucket_created':node.metadata['bucket_created'],
                    'region':node.region,'operation':'batch_delete_objects','etag':observations[node.key].etag,
                    'submitted_at':self.now().isoformat(),'deleted_at':timestamp}
                results[node.key]=Submission('pending',None,None,'Exact batch item completed; postflight reconciliation required',evidence)
        except Exception:return {n.key:Submission('unresolved',None,None,'Malformed batch completion; reconcile without replay') for n in nodes}
        return results
