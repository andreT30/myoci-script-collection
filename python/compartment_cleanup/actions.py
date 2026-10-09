"""Targeted, code-defined OCI actions with durable intent before every write.

Search and saved artifact fields are evidence only. Prepared actions are sealed to
this gateway and revalidated at submission; arbitrary dataclasses cannot authorize
an SDK call. An ambiguous absence never proves that a prior write completed.
"""
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from uuid import uuid4

import oci
from .model import CleanupError, Node, Observation, Submission
from .gateway import GatewayError
from .handlers.core import _POLICY, _COMPUTE, _VOLUMES, _identity, _VOLUME_FIELDS
from .handlers.network import NETWORK_OPERATIONS, _DEFAULTS
from .handlers.load_balancers import _CONTRACTS as LB_CONTRACTS, _snapshot
from .handlers.scheduled import _CONTRACTS as SCHEDULED, _ELIGIBLE, _utc, scheduled_time, ScheduledResources
from .handlers.logging_analytics import _CONTRACTS as LOG_CONTRACTS
from .handlers.storage import Storage, _TYPES as STORAGE_TYPES


@dataclass(frozen=True)
class PreparedAction:
    node: Node
    service: str
    operation: str
    params: dict
    endpoint: str | None
    effects: tuple[str, ...]


def _contract(kind):
    table={**_POLICY, **_COMPUTE, **_VOLUMES, **LB_CONTRACTS, **LOG_CONTRACTS}
    if kind in table:
        service, _, get, operation, parameter=table[kind]
        if operation:return service,get,operation,parameter
    if kind in NETWORK_OPERATIONS:
        _,get,operation,parameter=NETWORK_OPERATIONS[kind]
        return 'network',get,operation,parameter
    if kind in SCHEDULED:
        service,_,get,operation,parameter,_,_=SCHEDULED[kind]
        return service,get,operation,parameter
    if kind=='Bucket':return 'object_storage','get_bucket','delete_bucket','bucket_name'
    if kind=='Compartment':return 'identity','get_compartment','delete_compartment','compartment_id'
    raise CleanupError('No verified targeted action contract; remove this resource manually in its OCI service')


def _scope(gateway,plan,node):
    if gateway.tenancy_id!=plan.tenancy_id or gateway.home_region!=plan.home_region or plan.parent_id==plan.tenancy_id:
        raise CleanupError('Authenticated tenancy does not match retained parent scope')
    if node.resource_type=='Compartment' and node.key==plan.parent_id:
        raise CleanupError('Retained parent must never be deleted')
    if node.resource_type=='Compartment' and plan.compartments.get(node.key)!=node.compartment_id:
        raise CleanupError('Compartment target parent does not match the saved boundary')
    owner=node.compartment_id
    current=owner; seen=set()
    while True:
        if current in seen or current not in plan.compartments:
            raise CleanupError('Target is outside the verified retained-parent subtree')
        seen.add(current)
        row,_=gateway.read('identity',plan.home_region,'get_compartment',{'compartment_id':current})
        _identity(row,current)
        if row.get('compartment_id')!=plan.compartments[current] or row.get('lifecycle_state')!='ACTIVE':
            raise CleanupError('Compartment parent link or lifecycle changed')
        if current==plan.parent_id:break
        current=row['compartment_id']
    return set(plan.compartments)


def _target(gateway,plan,node):
    service,get,operation,parameter=_contract(node.resource_type)
    endpoint=None; params={parameter:node.key}
    if service=='identity' and node.region!=plan.home_region:
        raise CleanupError('IAM action requires the authenticated home region')
    if node.region not in getattr(gateway,'regions',[]):
        raise CleanupError('Target region is not an authenticated subscribed region')
    if service=='kms_management':
        vault_id=node.metadata.get('vault_id')
        if not isinstance(vault_id,str) or not vault_id.startswith('ocid1.vault.'):
            raise CleanupError('Key vault identity missing; inspect the key and vault manually')
        vault,_=gateway.read('kms_vault',node.region,'get_vault',{'vault_id':vault_id})
        _identity(vault,vault_id); endpoint=vault.get('management_endpoint')
        if not endpoint:raise CleanupError('Fresh verified vault management endpoint unavailable')
    if service=='log_analytics':
        namespace=node.metadata.get('namespace')
        if not isinstance(namespace,str) or not namespace:
            raise CleanupError('Logging Analytics namespace unavailable; inspect the resource manually')
        params['namespace_name']=namespace
        if node.resource_type=='LogAnalyticsEntity':params['is_show_associated_sources_count']=True
    if node.resource_type=='Bucket':
        namespace,_=gateway.read('object_storage',node.region,'get_namespace',{})
        name=node.metadata.get('bucket_name') or node.display_name
        if not isinstance(namespace,str) or not namespace or not isinstance(name,str) or not name:
            raise CleanupError('Bucket canonical namespace or exact name is unavailable')
        row,headers=Storage()._bucket(gateway,node.region,namespace,name)
        _identity(row,node.key,node.compartment_id)
        return row,headers,None,service,operation,parameter
    row,headers=gateway.read(service,node.region,get,params,endpoint=endpoint)
    _identity(row,node.key)
    if row['compartment_id']!=node.compartment_id:
        raise CleanupError('Live resource ownership changed')
    if node.resource_type=='Key' and row.get('vault_id')!=node.metadata['vault_id']:
        raise CleanupError('Live key vault membership changed')
    return row,headers,endpoint,service,operation,parameter


def _member(gateway,plan,node,scope,service,get,parameter,key):
    row,_=gateway.read(service,node.region,get,{parameter:key});_identity(row,key)
    if row['compartment_id'] not in scope:
        raise CleanupError('Automatic effect reaches an outside resource; resolve it manually')
    _scope(gateway,plan,replace(node,resource_type='_effect',compartment_id=row['compartment_id']))
    return row


def _effects(gateway,plan,node,row,scope):
    kind=node.resource_type; effects=[]
    if kind=='Bucket':
        if row.get('replication_enabled') is True or row.get('is_read_only') is True:
            raise CleanupError('Bucket replication or read-only protection needs manual resolution')
        rules=gateway.items('object_storage',node.region,'list_retention_rules',{'namespace_name':row['namespace'],'bucket_name':row['name']})
        for rule in rules:
            if type(rule) is not dict:raise CleanupError('Malformed bucket retention protection')
            lock=_utc(rule.get('time_rule_locked'))
            if lock and datetime.fromisoformat(lock.replace('Z','+00:00'))<=datetime.now(timezone.utc):
                raise CleanupError('Bucket retention rule is locked; remove it manually when permitted')
            effects.append('Owned unlocked bucket retention rule '+str(rule.get('id') or 'unknown'))
    if kind in _VOLUMES:
        if any(row.get(k) for k in _VOLUME_FIELDS if k!='kms_key_id'):
            raise CleanupError('Volume group, replica, or retention protection requires manual resolution')
    if kind in ('RouteTable','SecurityList','DhcpOptions'):
        vcn_id=row.get('vcn_id')
        if not vcn_id:raise CleanupError('Network owner identity unavailable')
        vcn,_=gateway.read('network',node.region,'get_vcn',{'vcn_id':vcn_id});_identity(vcn,vcn_id)
        if any(vcn.get(field)==node.key for field in _DEFAULTS):
            raise CleanupError('Default VCN resource is owned by its VCN; delete its verified owner instead')
    if kind=='Vcn':
        # Default resources are implicit owned effects, not independently deletable.
        for field,child_kind in _DEFAULTS.items():
            key=row.get(field)
            if not key:raise CleanupError('VCN default resource ownership is unresolved')
            _,get,_,parameter=NETWORK_OPERATIONS[child_kind]
            member=_member(gateway,plan,node,scope,'network',get,parameter,key)
            if member.get('vcn_id')!=node.key:raise CleanupError('VCN default membership changed')
            effects.append('Owned default '+child_kind+' '+key)
        # Known Search identities supply candidates, never an inferred owner.
        resolvers=[]
        for candidate in plan.nodes.values():
            if candidate.resource_type!='Resolver' or candidate.region!=node.region:continue
            resolver,_=gateway.read('dns',node.region,'get_resolver',{'resolver_id':candidate.key,'scope':'PRIVATE'})
            _identity(resolver,candidate.key)
            if resolver.get('attached_vcn_id')==node.key:resolvers.append(resolver)
        if len(resolvers)!=1:raise CleanupError('VCN default resolver identity is unknown or conflicting; inspect its DNS owner manually')
        resolver=resolvers[0]
        if resolver['compartment_id']!=node.compartment_id:raise CleanupError('VCN protected resolver has a different owner; inspect the cascade manually')
        _scope(gateway,plan,replace(node,resource_type='_effect',compartment_id=resolver['compartment_id']))
        if resolver.get('is_protected') is not True or resolver.get('lifecycle_state')!='ACTIVE':raise CleanupError('VCN resolver is not a verified protected default')
        if any(type(resolver.get(field)) is not list for field in ('rules','endpoints','attached_views')):
            raise CleanupError('VCN resolver configuration is malformed')
        if resolver['rules'] or resolver['endpoints'] or gateway.items('dns',node.region,'list_resolver_endpoints',{'resolver_id':resolver['id'],'scope':'PRIVATE'}):
            raise CleanupError('Configured VCN resolver endpoints or rules require manual closure')
        view_id=resolver.get('default_view_id')
        if not isinstance(view_id,str) or not view_id:raise CleanupError('VCN default view identity is missing')
        view,_=gateway.read('dns',node.region,'get_view',{'view_id':view_id,'scope':'PRIVATE'});_identity(view,view_id)
        if view['compartment_id']!=node.compartment_id:raise CleanupError('VCN default view has a different owner; inspect the cascade manually')
        _scope(gateway,plan,replace(node,resource_type='_effect',compartment_id=view['compartment_id']))
        if view.get('is_protected') is not True or view.get('lifecycle_state')!='ACTIVE':raise CleanupError('VCN default view is not a verified protected owner')
        for retained in resolver['attached_views']:
            if type(retained) is not dict or not isinstance(retained.get('view_id'),str) or retained['view_id']==view_id:
                raise CleanupError('Resolver attached view membership is malformed or shared with its default')
            effects.append('Detach and retain attached DNS view '+retained['view_id'])
        effects.extend(('Owned protected DNS resolver '+resolver['id'],'Owned protected default DNS view '+view_id))
    if kind in LB_CONTRACTS:
        metadata,issues=_snapshot(gateway,kind,row,node.region,scope)
        if issues:raise CleanupError('; '.join(issues))
        for subnet in metadata.get('subnet_ids',[]) or ([metadata['subnet_id']] if metadata.get('subnet_id') else []):
            owner=metadata['relationship_snapshot'][subnet]['compartment_id']
            _scope(gateway,plan,replace(node,resource_type='_effect',compartment_id=owner))
        effects.extend('Owned '+field+' configuration' for field,value in metadata['configuration'].items() if value)
        effects.append('Owned service network interfaces in verified in-scope subnets')
    if kind=='Instance':
        if row.get('instance_configuration_id'):
            raise CleanupError('Managed instance producer requires manual verification before termination')
        effects.extend(('Preserve boot volume','Preserve data volumes created at launch'))
        for attachment in gateway.items('compute',node.region,'list_vnic_attachments',{'compartment_id':row['compartment_id'],'instance_id':node.key}):
            _identity(attachment)
            if attachment.get('instance_id')!=node.key:raise CleanupError('VNIC attachment identity changed')
            if attachment.get('lifecycle_state')=='DETACHED':continue
            live=_member(gateway,plan,node,scope,'compute','get_vnic_attachment','vnic_attachment_id',attachment['id'])
            if live.get('instance_id')!=node.key or live.get('lifecycle_state')!='ATTACHED':raise CleanupError('VNIC attachment is transitional')
            vnic=_member(gateway,plan,node,scope,'network','get_vnic','vnic_id',live.get('vnic_id'))
            if vnic.get('vlan_id') or vnic.get('ipv6_addresses') or vnic.get('public_ip'):
                raise CleanupError('VNIC public-IP/VLAN/IPv6 cascade requires manual verification')
            for ip in gateway.items('network',node.region,'list_private_ips',{'vnic_id':vnic['id']}):
                _identity(ip)
                private=_member(gateway,plan,node,scope,'network','get_private_ip','private_ip_id',ip['id'])
                if private.get('vnic_id')!=vnic['id'] or private.get('lifetime')!='EPHEMERAL':
                    raise CleanupError('Private IP cascade ownership is unresolved')
                effects.append('Owned ephemeral private IP '+private['id'])
            effects.append('Owned VNIC '+vnic['id'])
    if kind in ('VolumeAttachment','BootVolumeAttachment'):
        instance=_member(gateway,plan,node,scope,'compute','get_instance','instance_id',row.get('instance_id'))
        if kind=='BootVolumeAttachment' and instance.get('lifecycle_state')!='STOPPED':raise CleanupError('Boot detach requires a stopped instance')
        if kind=='VolumeAttachment' and row.get('attachment_type') not in ('iscsi','paravirtualized'):raise CleanupError('Unsupported volume attachment subtype')
    if kind=='LogAnalyticsEntity':
        creation=row.get('creation_source')
        if type(creation) is not dict or creation.get('type')!='NONE':raise CleanupError('Automatic Logging Analytics producer needs manual closure')
        params={'namespace_name':node.metadata['namespace'],'log_analytics_entity_id':node.key,'direct_or_all_associations':'ALL'}
        associations=gateway.items('log_analytics',node.region,'list_entity_associations',params)
        sources=gateway.items('log_analytics',node.region,'list_entity_source_associations',{'namespace_name':node.metadata['namespace'],'compartment_id':row['compartment_id'],'entity_id':node.key,'life_cycle_state':'ALL'})
        if associations or sources or type(row.get('associated_sources_count')) is not int or row.get('associated_sources_count')!=0 or row.get('are_logs_collected') is not False:
            raise CleanupError('Logging Analytics associations remain; remove them manually before deletion')
    elif kind in LOG_CONTRACTS:
        # Existing effects implementation is targeted for non-entity resources.
        from .handlers.logging_analytics import LoggingAnalytics
        LoggingAnalytics()._effects(gateway,node,row,scope)
    if kind in SCHEDULED:
        if row.get('replica_details') is not None or row.get('is_replica') is True or row.get('certificate_revocation_list_details') is not None:
            raise CleanupError('Replication or revocation-list effects require manual resolution')
        if kind=='Secret':
            if row.get('is_replica') is not False:raise CleanupError('Only a positively verified source secret can be scheduled')
            if ScheduledResources()._targets(row):raise CleanupError('Secret replication needs manual closure')
        if kind in ('Vault','Key'):
            handler=ScheduledResources()
            vault=row if kind=='Vault' else gateway.read('kms_vault',node.region,'get_vault',{'vault_id':row['vault_id']})[0]
            handler._unreplicated(gateway,node.region,vault,row if kind=='Key' else None)
            if vault['compartment_id'] not in scope:raise CleanupError('Vault is outside cleanup scope')
            if kind=='Vault':
                if vault.get('vault_type')=='EXTERNAL':raise CleanupError('External vault membership requires manual verification')
                counts={'HSM':0,'SOFTWARE':0}; endpoint=vault['management_endpoint']; seen_keys=set()
                for compartment in sorted(scope):
                    _scope(gateway,plan,replace(node,resource_type='_effect',compartment_id=compartment))
                    for summary in gateway.items('kms_management',node.region,'list_keys',{'compartment_id':compartment},endpoint=endpoint):
                        key,_=gateway.read('kms_management',node.region,'get_key',{'key_id':summary['id']},endpoint=endpoint);_identity(key,summary['id'],compartment)
                        if key['id'] in seen_keys:raise CleanupError('Duplicate bound vault key identity')
                        seen_keys.add(key['id'])
                        if key.get('vault_id')!=node.key:raise CleanupError('Bound vault key membership changed')
                        if key.get('lifecycle_state')=='DELETED':continue
                        handler._unreplicated(gateway,node.region,vault,key)
                        if key.get('protection_mode') not in counts:raise CleanupError('Unknown key protection mode')
                        counts[key['protection_mode']]+=1
                        if key.get('lifecycle_state') not in _ELIGIBLE['Key']:raise CleanupError('Existing key schedule requires manual alignment')
                        effects.append('Schedule owned key '+key['id'])
                usage,_=gateway.read('kms_vault',node.region,'get_vault_usage',{'vault_id':node.key})
                if any(type(usage.get(f)) is not int or usage[f]!=counts[m] for f,m in (('key_count','HSM'),('software_key_count','SOFTWARE'))):
                    raise CleanupError('Vault usage does not prove complete in-scope key membership; inspect external keys manually')
    if row.get('is_protected') or row.get('is_delete_protection_enabled'):
        raise CleanupError('Resource deletion protection is enabled')
    return tuple(effects)


def prepare_action(gateway,plan,node,registry):
    scope=_scope(gateway,plan,node)
    if node.resource_type in STORAGE_TYPES and node.resource_type!='Bucket':
        return _prepare_storage_child(gateway,plan,node,registry,scope)
    row,headers,endpoint,service,operation,parameter=_target(gateway,plan,node)
    kind=node.resource_type
    eligible=_ELIGIBLE.get(kind,('ACTIVE',) if kind in ('Policy','Compartment',*LOG_CONTRACTS,*LB_CONTRACTS) else ('AVAILABLE',))
    if kind=='Instance':eligible=('RUNNING','STOPPED')
    if kind in ('VolumeAttachment','BootVolumeAttachment'):eligible=('ATTACHED',)
    if kind in ('VolumeBackup','BootVolumeBackup'):eligible=('AVAILABLE',)
    if kind!='Bucket' and row.get('lifecycle_state') not in eligible:raise CleanupError('Live lifecycle does not permit this operation')
    etag=headers.get('etag')
    if not isinstance(etag,str) or not etag:raise CleanupError('Fresh resource ETag is required')
    effects=_effects(gateway,plan,node,row,scope)
    params={parameter:node.key,'if_match':etag}
    if kind=='Bucket':
        params={'namespace_name':row['namespace'],'bucket_name':row['name'],'if_match':etag}
        node=replace(node,metadata=dict(node.metadata,bucket_id=row['id'],bucket_name=row['name'],namespace=row['namespace'],bucket_created=row['time_created'],versioning=row['versioning']))
    if kind=='Instance':params.update(preserve_boot_volume=True,preserve_data_volumes_created_at_launch=True)
    if kind in SCHEDULED:
        _,_,_,_,_,detail,model=SCHEDULED[kind]
        if model:params[detail]=model(time_of_deletion=scheduled_time(kind,datetime.now(timezone.utc)))
    if service=='log_analytics':params['namespace_name']=node.metadata['namespace']
    if kind=='LogAnalyticsEntity':params['is_force_delete']=False
    prepared=PreparedAction(node,service,operation,params,endpoint,effects)
    cache=getattr(gateway,'_guided_prepared',None)
    if cache is None:cache={};gateway._guided_prepared=cache
    cache[id(prepared)]=(prepared,plan,deepcopy(oci.util.to_dict(params)),effects)
    return prepared


class _CaptureWrite:
    def __init__(self,gateway):self.gateway=gateway;self.captured=None
    def __getattr__(self,name):return getattr(self.gateway,name)
    def write(self,service,region,operation,params,endpoint=None):
        if self.captured is not None:raise CleanupError('Storage action submitted multiple operations')
        self.captured=(service,operation,dict(params),endpoint)
        return {},{}


def _prepare_storage_child(gateway,plan,node,registry,scope):
    handler=Storage()
    handler.bind_plan(plan.nodes.values())
    safe=replace(node,blockers=())
    observation=handler.inspect(gateway,safe,scope)
    if observation.status!='present':raise CleanupError(observation.detail)
    capture=_CaptureWrite(gateway)
    handler.submit(capture,safe,observation,'prepared-action')
    if capture.captured is None:raise CleanupError('Storage action did not establish a fixed operation')
    service,operation,params,endpoint=capture.captured
    params.pop('opc_client_request_id',None)
    prepared=PreparedAction(safe,service,operation,params,endpoint,('Exact bucket-owned '+node.resource_type,))
    cache=getattr(gateway,'_guided_prepared',None)
    if cache is None:cache={};gateway._guided_prepared=cache
    cache[id(prepared)]=(prepared,plan,deepcopy(oci.util.to_dict(params)),prepared.effects)
    return prepared


def _save(workspace,state):
    from .executor import JournalError
    try:workspace.save_state(state)
    except Exception as error:
        raise JournalError('Cannot persist guided action journal; stop all mutations') from error


def submit_action(gateway,workspace,state,prepared):
    seal=getattr(gateway,'_guided_prepared',{}).pop(id(prepared),None)
    if seal is None or seal[0] is not prepared or oci.util.to_dict(prepared.params)!=seal[2] or prepared.effects!=seal[3]:
        raise CleanupError('Prepared action was forged, changed, or already consumed')
    plan=seal[1]
    if (state.tenancy_id,state.parent_id)!=(plan.tenancy_id,plan.parent_id):raise CleanupError('Journal scope does not match action')
    fresh=prepare_action(gateway,plan,prepared.node,None)
    getattr(gateway,'_guided_prepared',{}).pop(id(fresh),None)
    if (fresh.service,fresh.operation,fresh.endpoint,fresh.params.get('if_match'),fresh.effects)!=(prepared.service,prepared.operation,prepared.endpoint,prepared.params.get('if_match'),prepared.effects):
        raise CleanupError('Prepared ownership, ETag or effects changed before submission')
    token=str(uuid4()); params=dict(prepared.params)
    if prepared.service in ('load_balancer','network_load_balancer','log_analytics','service_connector','certificates','kms_vault','kms_management','vault'):
        params['opc_request_id']=token
    if prepared.service=='object_storage':params['opc_client_request_id']=token
    if prepared.node.resource_type in ('Vault','Key'):params['opc_retry_token']=token
    record=state.records.setdefault(prepared.node.key,{'status':'discovered','attempts':[]})
    history=record.setdefault('attempts',[])
    if any(a.get('status') in ('attempting','uncertain','unresolved','pending') for a in history):
        raise CleanupError('Prior submission must be positively reconciled before replay')
    attempt={'attempt_id':token,'status':'attempting','started_at':datetime.now(timezone.utc).isoformat(),'node_key':prepared.node.key,'resource_type':prepared.node.resource_type,'compartment_id':prepared.node.compartment_id,'service':prepared.service,'region':prepared.node.region,'operation':prepared.operation,'params':oci.util.to_dict(params),'effects':list(prepared.effects)}
    if prepared.service=='object_storage':attempt['storage_identity']={k:prepared.node.metadata[k] for k in ('bucket_id','bucket_name','namespace','bucket_created','versioning') if k in prepared.node.metadata}
    history.append(attempt);record.update(status='attempting')
    _save(workspace,state)
    try:
        _,headers=gateway.write(prepared.service,prepared.node.region,prepared.operation,params,endpoint=prepared.endpoint)
    except Exception as error:
        from .dependencies import is_confirmed_rejection
        status='failed' if is_confirmed_rejection(error) else 'uncertain'
        attempt.update(status=status,detail='Confirmed request rejection' if status=='failed' else 'Response uncertain; reconcile before replay')
        record.update(status=status,detail=attempt['detail'])
        if isinstance(error,GatewayError):attempt['error']={'http_status':error.status,'code':error.code,'request_id':error.request_id,'message':error.message}
        _save(workspace,state)
        raise
    evidence={'work_request_id':headers['opc-work-request-id']} if headers.get('opc-work-request-id') else None
    if prepared.service=='object_storage' and headers.get('__http_status__')==204:
        metadata=prepared.node.metadata
        evidence={'node_key':prepared.node.key,'bucket_id':metadata.get('bucket_id',prepared.node.key),'bucket_created':metadata.get('bucket_created'),'region':prepared.node.region,'operation':prepared.operation,'http_status':204,'etag':prepared.params.get('if_match'),'submitted_at':datetime.now(timezone.utc).isoformat()}
        if prepared.node.resource_type=='ObjectStorageVersion':
            if headers.get('version-id')!=metadata['version_id']:evidence=None
            else:evidence['version_id']=headers['version-id']
    result=Submission('pending',headers.get('opc-request-id'),None,'Operation accepted; positive terminal verification required',evidence)
    attempt.update(status=result.status,request_id=result.request_id,operation_evidence=evidence)
    record.update(status=result.status,detail=result.detail)
    _save(workspace,state)
    return result


class _ReadAuthorizationTracker:
    def __init__(self,gateway):self.gateway=gateway;self.error=None
    def __getattr__(self,name):return getattr(self.gateway,name)
    def _read(self,method,*args,**kwargs):
        try:return getattr(self.gateway,method)(*args,**kwargs)
        except GatewayError as error:
            if error.status in (401,403):self.error=error
            raise
    def read(self,*args,**kwargs):return self._read('read',*args,**kwargs)
    def items(self,*args,**kwargs):return self._read('items',*args,**kwargs)
    def write(self,*args,**kwargs):return self._read('write',*args,**kwargs)


def _checked_read(method,gateway,*args):
    tracker=_ReadAuthorizationTracker(gateway)
    result=method(tracker,*args)
    if tracker.error is not None:raise tracker.error
    return result


def _eligible_history(record):
    invalidated=set()
    entries=record.get('proof_invalidations',[])
    if not isinstance(entries,list):raise CleanupError('Malformed proof invalidation history')
    for entry in entries:
        if not isinstance(entry,dict) or not isinstance(entry.get('attempt_ids'),list):
            raise CleanupError('Malformed proof invalidation')
        if any(not isinstance(token,str) or not token for token in entry['attempt_ids']):
            raise CleanupError('Malformed invalidated attempt identity')
        invalidated.update(entry['attempt_ids'])
    history=record.get('attempts',[])
    if not isinstance(history,list) or any(not isinstance(attempt,dict) for attempt in history):
        raise CleanupError('Malformed operation history')
    return [attempt for attempt in history if attempt.get('attempt_id') not in invalidated]


def _terminal_history(record):
    for attempt in _eligible_history(record):
        if attempt.get('status') in ('attempting','uncertain','unresolved','pending'):
            attempt['status']='deleted'


def reconcile_action(gateway,plan,node,record,registry):
    try:
        scope=_scope(gateway,plan,node)
        if node.resource_type=='Bucket' and not node.metadata.get('bucket_created'):
            for attempt in reversed(_eligible_history(record)):
                identity=attempt.get('storage_identity')
                if type(identity) is dict and identity.get('bucket_id')==node.key:
                    node=replace(node,metadata=dict(node.metadata,**identity));break
        if node.resource_type in STORAGE_TYPES and node.resource_type!='Bucket':
            handler=Storage();handler.bind_plan(plan.nodes.values())
            present=_checked_read(handler.observe_live_identity,gateway,node,scope)
            if present is not None:return present
            for attempt in reversed(_eligible_history(record)):
                evidence=attempt.get('operation_evidence') or attempt.get('resource_evidence',{}).get(node.key)
                if not isinstance(evidence,dict):continue
                observation=_checked_read(handler.reconcile_submission,gateway,node,evidence,scope)
                if observation.status=='deleted':_terminal_history(record)
                return observation
            raise CleanupError('Storage child absence has no exact completion evidence')
        try:
            row,headers,_,_,_,_=_target(gateway,plan,node)
        except GatewayError as error:
            if error.status==404 and node.resource_type=='Bucket':
                handler=Storage();handler.bind_plan(plan.nodes.values())
                for attempt in reversed(_eligible_history(record)):
                    evidence=attempt.get('operation_evidence') or attempt.get('resource_evidence',{}).get(node.key)
                    if not isinstance(evidence,dict):continue
                    observation=_checked_read(handler.reconcile_submission,gateway,node,evidence,scope)
                    if observation.status=='deleted':_terminal_history(record)
                    return observation
            if error.status!=404 or node.resource_type not in LB_CONTRACTS:raise
            from .handlers.load_balancers import LoadBalancers
            for attempt in reversed(_eligible_history(record)):
                evidence=attempt.get('operation_evidence') or attempt.get('resource_evidence',{}).get(node.key) or {}
                work_id=evidence.get('work_request_id')
                if not isinstance(work_id,str) or not work_id:continue
                expected_service,_,expected_operation,_=_contract(node.resource_type)
                if attempt.get('service')!=expected_service or attempt.get('operation')!=expected_operation or attempt.get('node_key')!=node.key:continue
                observation=_checked_read(LoadBalancers().inspect_work_request,gateway,node,work_id,scope)
                if observation.status=='deleted':_terminal_history(record)
                return observation
            raise
        lifecycle=row.get('lifecycle_state') or ''; timestamp=_utc(row.get('time_of_deletion'))
        terminal='TERMINATED' if node.resource_type in (*NETWORK_OPERATIONS,*_VOLUMES,'Instance') else 'DETACHED' if node.resource_type in ('VolumeAttachment','BootVolumeAttachment') else 'DELETED'
        status='deleted' if lifecycle==terminal else 'pending' if lifecycle in ('PENDING_DELETION','SCHEDULING_DELETION','DELETING','TERMINATING','DETACHING') else 'present'
        if status=='deleted':_terminal_history(record)
        if timestamp is not None:
            for attempt in reversed(_eligible_history(record)):
                if attempt.get('status') in ('attempting','uncertain','unresolved','pending','deleted'):
                    old=attempt.get('scheduled_at')
                    if old is not None and old!=timestamp:attempt.setdefault('schedule_history',[]).append({'scheduled_at':old})
                    attempt['scheduled_at']=timestamp;break
        return Observation(status,row['compartment_id'],lifecycle,timestamp,headers.get('etag'),'Targeted live resource observation')
    except Exception as error:
        from .executor import JournalError
        if isinstance(error,JournalError) or isinstance(error,GatewayError) and error.status in (401,403):raise
        return Observation('unresolved',node.compartment_id,'',record.get('scheduled_at'),None,'Live identity or absence is ambiguous; inspect the resource and prior request manually')
