"""Logging Analytics cleanup with exact producer evidence and conservative closure.

Namespace enumeration is tenancy-wide and non-paginated. Rule.entity_id is the
only audited exact producer relation. SCH/EM creation strings cannot establish
that relation; forced association removal and a server bulk route remain blocked.
The visible tenancy scan cannot prove cross-tenancy producer absence, so entities
with an automatic creation source remain unresolved even after local producers
stop. Source buckets and destination log groups are never deleted by this handler.
"""
from copy import deepcopy
from dataclasses import replace

from .base import Handler
from .core import _identity, _scope, _compartments, _blocked
from ..model import CleanupError, Node, Edge, Probe, Observation, Submission

_CONTRACTS = {
    'LogAnalyticsEntity': ('log_analytics','list_log_analytics_entities','get_log_analytics_entity','delete_log_analytics_entity','log_analytics_entity_id'),
    'LogAnalyticsObjectCollectionRule': ('log_analytics','list_log_analytics_object_collection_rules','get_log_analytics_object_collection_rule','delete_log_analytics_object_collection_rule','log_analytics_object_collection_rule_id'),
    'LogAnalyticsEmBridge': ('log_analytics','list_log_analytics_em_bridges','get_log_analytics_em_bridge','delete_log_analytics_em_bridge','log_analytics_em_bridge_id'),
    'ServiceConnector': ('service_connector','list_service_connectors','get_service_connector','delete_service_connector','service_connector_id'),
}
_FIELDS = {
    'LogAnalyticsEntity': ('cloud_resource_id','management_agent_id','management_agent_compartment_id','source_id','associated_sources_count','are_logs_collected'),
    'LogAnalyticsObjectCollectionRule': ('entity_id','log_group_id','os_namespace','os_bucket_name','stream_id'),
    'LogAnalyticsEmBridge': ('em_entities_compartment_id','bucket_name'),
    'ServiceConnector': (),
}
_PRODUCER_KEYS = ('id','kind','compartment_id','namespace')


def _text(value):
    if not isinstance(value,str) or not value: raise CleanupError('Typed Logging Analytics identifier unavailable')
    return value


def _metadata(kind,row,namespace):
    result={k:row[k] for k in _FIELDS[kind] if row.get(k) is not None}
    if kind!='ServiceConnector': result['namespace']=_text(namespace)
    if kind=='LogAnalyticsEntity':
        creation=row.get('creation_source')
        if type(creation) is dict and isinstance(creation.get('type'),str): result['creation_source_type']=creation['type']
    if kind=='ServiceConnector':
        target=row.get('target')
        if type(target) is dict:
            result['target_kind']=target.get('kind'); result['log_group_id']=target.get('log_group_id')
    return result


class LoggingAnalytics(Handler):
    name='logging_analytics'
    resource_types=tuple(_CONTRACTS)
    action='delete'
    metadata_keys=tuple(sorted({'namespace','creation_source','creation_source_type','producers','target_kind','log_group_id'}
                              |{k for v in _FIELDS.values() for k in v}))
    retained_reference_fields=('cloud_resource_id','management_agent_id','log_group_id','os_bucket_name','stream_id','bucket_name')

    def classify(self,node):
        allowed=set(_FIELDS[node.resource_type])|{'namespace'}
        if node.resource_type=='LogAnalyticsEntity': allowed.update(('creation_source_type','producers'))
        if node.resource_type=='ServiceConnector': allowed.update(('target_kind','log_group_id')); allowed.discard('namespace')
        metadata={k:v for k,v in node.metadata.items() if k in allowed}
        creation=node.metadata.get('creation_source')
        if node.resource_type=='LogAnalyticsEntity' and type(creation) is dict and isinstance(creation.get('type'),str):
            metadata['creation_source_type']=creation['type']
        if 'producers' in metadata:
            rows=metadata['producers']
            metadata['producers']=[{k:r[k] for k in _PRODUCER_KEYS if isinstance(r.get(k),str)} for r in rows if type(r) is dict] if type(rows) is list else []
        return replace(node,handler=self.name,action='delete',metadata=metadata)

    def _namespaces(self,gateway,region):
        data,headers=gateway.read('log_analytics',region,'list_namespaces',{'compartment_id':gateway.tenancy_id})
        if type(data) is not dict or type(data.get('items')) is not list or headers.get('opc-next-page'):
            raise CleanupError('Namespace response is incomplete')
        names=[]
        for row in data['items']:
            if type(row) is not dict or row.get('compartment_id')!=gateway.tenancy_id: raise CleanupError('Namespace tenancy identity changed')
            names.append(_text(row.get('namespace_name')))
        if len(names)!=len(set(names)): raise CleanupError('Duplicate namespace identity')
        return names

    def _read(self,gateway,node):
        service,_,get,_,parameter=_CONTRACTS[node.resource_type]
        params={parameter:node.key}
        if service=='log_analytics': params['namespace_name']=_text(node.metadata.get('namespace'))
        if node.resource_type=='LogAnalyticsEntity': params['is_show_associated_sources_count']=True
        row,headers=gateway.read(service,node.region,get,params)
        _identity(row,node.key)
        return row,headers

    def _inventory(self,gateway,region,namespace,kind):
        service,listing,_,_,_=_CONTRACTS[kind]; result={}
        for compartment in _compartments(gateway):
            params={'compartment_id':compartment}
            if service=='log_analytics': params['namespace_name']=namespace
            for summary in gateway.items(service,region,listing,params):
                _identity(summary,owner=compartment)
                n=Node(summary['id'],kind,region,compartment,'',summary.get('lifecycle_state') or '',self.name,'delete',{} if kind=='ServiceConnector' else {'namespace':namespace})
                row,_=self._read(gateway,n); _identity(row,summary['id'],compartment)
                if row['id'] in result: raise CleanupError('Duplicate producer identity')
                result[row['id']]=row
        return result

    def _producers(self,gateway,node,previous=()):
        ns=_text(node.metadata.get('namespace')); result=[]; ambiguous=False
        for kind in ('LogAnalyticsObjectCollectionRule','LogAnalyticsEmBridge','ServiceConnector'):
            rows=self._inventory(gateway,node.region,ns,kind); historical=set()
            # A successful empty list cannot erase historical exact producer proof.
            for old in previous:
                if old.get('kind')!=kind: continue
                owner=_text(old.get('compartment_id')); key=_text(old.get('id'))
                if kind!='ServiceConnector' and old.get('namespace')!=ns: raise CleanupError('Historical producer namespace changed')
                historical.add(key)
                candidate=Node(key,kind,node.region,owner,'','',self.name,'delete',{} if kind=='ServiceConnector' else {'namespace':_text(old.get('namespace'))})
                row,_=self._read(gateway,candidate); _identity(row,key,owner)
                if kind=='LogAnalyticsObjectCollectionRule' and row.get('lifecycle_state')!='DELETED' and row.get('entity_id')!=node.key:
                    raise CleanupError('Historical producer relation changed')
                rows[key]=row
            for row in rows.values():
                state=row.get('lifecycle_state')
                if kind=='LogAnalyticsObjectCollectionRule' and (row.get('entity_id')==node.key or row['id'] in historical and state=='DELETED'):
                    result.append({'id':row['id'],'kind':kind,'compartment_id':row['compartment_id'],'namespace':ns,'lifecycle_state':state})
                elif state!='DELETED' and (kind=='LogAnalyticsObjectCollectionRule' and not row.get('entity_id')
                        or kind=='LogAnalyticsEmBridge'
                        or kind=='ServiceConnector' and (type(row.get('target')) is not dict or row['target'].get('kind')=='loggingAnalytics')):
                    ambiguous=True
        return result,ambiguous

    def _group_owner(self,gateway,node,key,scope):
        row,_=gateway.read('log_analytics',node.region,'get_log_analytics_log_group',
                           {'namespace_name':_text(node.metadata.get('namespace')),'log_analytics_log_group_id':_text(key)})
        _identity(row,key)
        if row['compartment_id'] not in scope: raise CleanupError('External collection log group effect')

    def _effects(self,gateway,node,row,scope):
        kind=node.resource_type
        if kind=='LogAnalyticsObjectCollectionRule':
            ns=_text(node.metadata.get('namespace')); key=_text(row.get('entity_id'))
            entity,_=gateway.read('log_analytics',node.region,'get_log_analytics_entity',{'namespace_name':ns,'log_analytics_entity_id':key})
            _identity(entity,key)
            if entity['compartment_id'] not in scope: raise CleanupError('External collection entity effect')
            self._group_owner(gateway,node,row.get('log_group_id'),scope)
        elif kind=='LogAnalyticsEmBridge':
            if _text(row.get('em_entities_compartment_id')) not in scope: raise CleanupError('External bridge collection effect')
        elif kind=='ServiceConnector':
            target=row.get('target')
            if type(target) is not dict or target.get('kind')!='loggingAnalytics': raise CleanupError('Connector target effect unresolved')
            namespaces=self._namespaces(gateway,node.region)
            if len(namespaces)!=1: raise CleanupError('Connector target namespace unresolved')
            self._group_owner(gateway,replace(node,metadata={'namespace':namespaces[0]}),target.get('log_group_id'),scope)
            source=row.get('source')
            if type(source) is not dict or source.get('kind')!='logging' or type(source.get('log_sources')) is not list or not source['log_sources']:
                raise CleanupError('Connector source collection effect unresolved')
            if any(type(s) is not dict or s.get('compartment_id') not in scope for s in source['log_sources']):
                raise CleanupError('External connector source collection effect')
        else:
            producers,ambiguous=self._producers(gateway,node,node.metadata.get('producers',()))
            if ambiguous: raise CleanupError('Producer closure is ambiguous or external')
            if any(p['compartment_id'] not in scope or p['lifecycle_state']!='DELETED' for p in producers):
                raise CleanupError('Exact producer must be in scope and positively DELETED')
            creation=row.get('creation_source')
            if type(creation) is not dict or creation.get('type')!='NONE':
                raise CleanupError('Automatic or unknown producer mapping and cross-tenancy closure unresolved')
            ns=_text(node.metadata.get('namespace'))
            associations=gateway.items('log_analytics',node.region,'list_entity_associations',
                {'namespace_name':ns,'log_analytics_entity_id':node.key,'direct_or_all_associations':'ALL'})
            sources=gateway.items('log_analytics',node.region,'list_entity_source_associations',
                {'namespace_name':ns,'compartment_id':row['compartment_id'],'entity_id':node.key,'life_cycle_state':'ALL'})
            if associations or sources or type(row.get('associated_sources_count')) is not int or row['associated_sources_count']!=0 or row.get('are_logs_collected') is not False:
                raise CleanupError('Affected association closure unproven; force deletion blocked')

    def inspect(self,gateway,node,scope):
        try:
            row,headers=self._read(gateway,node); owner=row['compartment_id']; state=row.get('lifecycle_state') or ''
            if owner!=node.compartment_id or owner not in scope: return Observation('moved',owner,state,None,None,'Live ownership changed; refresh report')
            if state=='DELETED': return Observation('deleted',owner,state,None,headers.get('etag'),'Positive terminal identity observation')
            if state=='DELETING': return Observation('pending',owner,state,None,headers.get('etag'),'Deletion remains pending')
            eligible={'LogAnalyticsEntity':('ACTIVE',),'LogAnalyticsObjectCollectionRule':('ACTIVE','INACTIVE'),
                      'LogAnalyticsEmBridge':('ACTIVE','NEEDS_ATTENTION'),'ServiceConnector':('ACTIVE','INACTIVE','NEEDS_ATTENTION')}
            if state not in eligible[node.resource_type]: raise CleanupError('Lifecycle eligibility unresolved')
            self._effects(gateway,node,row,scope)
            return Observation('present',owner,state,None,headers.get('etag'),'Fresh identity, producer and collection scope evidence')
        except CleanupError as error:
            return Observation('unresolved',node.compartment_id,'',None,None,str(error))
        except Exception:
            return Observation('unresolved',node.compartment_id,'',None,None,'Live identity or complete producer visibility unavailable')

    def submit(self,gateway,node,observation,attempt_id):
        if observation.status!='present' or not observation.etag: raise CleanupError('Fresh eligible observation and ETag required')
        renewed=self.inspect(gateway,node,_scope(gateway))
        if renewed.status!='present' or renewed.etag!=observation.etag: raise CleanupError('Live collection, owner or ETag evidence changed')
        service,_,_,delete,parameter=_CONTRACTS[node.resource_type]
        params={parameter:node.key,'if_match':renewed.etag,'opc_request_id':_text(attempt_id)}
        if service=='log_analytics': params['namespace_name']=_text(node.metadata.get('namespace'))
        if node.resource_type=='LogAnalyticsEntity': params['is_force_delete']=False
        if node.resource_type=='LogAnalyticsEmBridge': params['is_delete_entities']=False
        _,headers=gateway.write(service,node.region,delete,params)
        return Submission('pending',headers.get('opc-request-id'),None,'Delete accepted; positive terminal observation required')

    def refresh_node(self,gateway,node,previous,scope):
        if node.resource_type!='LogAnalyticsEntity': return node
        try:
            producers,ambiguous=self._producers(gateway,node,previous.metadata.get('producers',()))
            metadata=dict(node.metadata,producers=[{k:p[k] for k in _PRODUCER_KEYS} for p in producers])
            node=replace(node,metadata=metadata)
            if ambiguous: node=_blocked(node,'Producer closure is ambiguous')
            return node
        except Exception:
            return _blocked(node,'Historical producer identity cannot be renewed')

    def reconcile_record(self,gateway,node,scope,record):
        observation=self.inspect(gateway,node,scope)
        result=deepcopy(record)
        result.update(status=observation.status,lifecycle_state=observation.lifecycle_state)
        return result

    def discover(self,gateway,compartment_id,region):
        nodes=[]; edges=[]; probes=[]
        try: namespaces=self._namespaces(gateway,region)
        except Exception:
            return [],[],[Probe(self.name,region,compartment_id,'failed','Namespace visibility unavailable')]
        inventories={}; failed=False
        for ns in namespaces:
            for kind in ('LogAnalyticsObjectCollectionRule','LogAnalyticsEmBridge'):
                try: inventories[(ns,kind)]=self._inventory(gateway,region,ns,kind)
                except Exception: failed=True
        try: connectors=self._inventory(gateway,region,None,'ServiceConnector')
        except Exception: connectors={}; failed=True
        for ns in namespaces:
            for kind in ('LogAnalyticsEntity','LogAnalyticsObjectCollectionRule','LogAnalyticsEmBridge'):
                try:
                    service,listing,_,_,_=_CONTRACTS[kind]
                    params={'namespace_name':ns,'compartment_id':compartment_id}
                    if kind=='LogAnalyticsEntity': params['is_show_associated_sources_count']=True
                    for summary in gateway.items(service,region,listing,params):
                        _identity(summary,owner=compartment_id)
                        n=Node(summary['id'],kind,region,compartment_id,'',summary.get('lifecycle_state') or '',self.name,'delete',{'namespace':ns})
                        row,_=self._read(gateway,n); _identity(row,n.key,compartment_id)
                        n=replace(n,display_name=row.get('name') or row.get('display_name') or '',lifecycle_state=row.get('lifecycle_state') or '',metadata=_metadata(kind,row,ns))
                        if kind=='LogAnalyticsEntity':
                            producers=[r for r in inventories.get((ns,'LogAnalyticsObjectCollectionRule'),{}).values() if r.get('entity_id')==n.key]
                            n=replace(n,metadata=dict(n.metadata,producers=[{'id':r['id'],'kind':'LogAnalyticsObjectCollectionRule','namespace':ns,'compartment_id':r['compartment_id']} for r in producers]))
                            for r in producers:
                                if r['compartment_id']==compartment_id: edges.append(Edge(r['id'],n.key,'Exact object collection rule entity_id'))
                                elif r['compartment_id'] in _scope(gateway): edges.append(Edge(r['id'],n.key,'Exact object collection rule entity_id'))
                                else: n=_blocked(n,'External object collection producer')
                            creation=row.get('creation_source')
                            if failed or type(creation) is not dict or creation.get('type')!='NONE': n=_blocked(n,'Producer mapping or complete visibility unproven')
                            if any(r.get('lifecycle_state')!='DELETED' and not r.get('entity_id') for r in inventories.get((ns,'LogAnalyticsObjectCollectionRule'),{}).values()) or any(r.get('lifecycle_state')!='DELETED' for r in inventories.get((ns,'LogAnalyticsEmBridge'),{}).values()) or any(r.get('lifecycle_state')!='DELETED' and (type(r.get('target')) is not dict or r['target'].get('kind')=='loggingAnalytics') for r in connectors.values()):
                                n=_blocked(n,'Ambiguous producer closure')
                        elif self.inspect(gateway,n,_scope(gateway)).status=='unresolved': n=_blocked(n,'Collection destination scope unproven')
                        nodes.append(n)
                except Exception: failed=True
        for row in connectors.values():
            if row['compartment_id']!=compartment_id: continue
            n=Node(row['id'],'ServiceConnector',region,compartment_id,row.get('display_name') or '',row.get('lifecycle_state') or '',self.name,'delete',_metadata('ServiceConnector',row,None))
            if self.inspect(gateway,n,_scope(gateway)).status=='unresolved': n=_blocked(n,'Connector collection scope unproven')
            nodes.append(n)
        if failed:
            nodes=[_blocked(n,'Complete producer discovery unavailable') if n.resource_type=='LogAnalyticsEntity' else n for n in nodes]
        probes.append(Probe(self.name,region,compartment_id,'failed' if failed else 'complete','Typed LA inventory; SCH/EM exact entity mapping, cross-tenancy closure and force deletion remain unsupported'))
        return nodes,edges,probes
