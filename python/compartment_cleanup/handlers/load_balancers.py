"""LB/NLB parent configuration, retained references and exact async deletion proof.

Named configuration uses parent API identity, not independently owned OCIDs. The
approved scope contract permits inherited service VNIC scope through fresh subnets;
no address lookup or guessed VNIC identity establishes cascade membership. Actual
Search VNIC/IP resources still require their own typed ownership proof. Reserved
public IPs and Certificates service objects persist; their IDs are never cascaded.
"""
from dataclasses import replace

from .base import Handler
from .core import _identity, _blocked, _scope
from ..model import CleanupError, Node, Edge, Observation, Probe, Submission, child_key

_CONTRACTS = {
    'LoadBalancer': ('load_balancer', 'list_load_balancers', 'get_load_balancer', 'delete_load_balancer', 'load_balancer_id'),
    'NetworkLoadBalancer': ('network_load_balancer', 'list_network_load_balancers', 'get_network_load_balancer', 'delete_network_load_balancer', 'network_load_balancer_id'),
}
_CONFIG = {
    'LoadBalancer': ('listeners', 'backend_sets', 'hostnames', 'certificates', 'path_route_sets', 'rule_sets', 'routing_policies', 'ssl_cipher_suites'),
    'NetworkLoadBalancer': ('listeners', 'backend_sets'),
}
# The SDK parent model is the accepted owned-configuration contract. Unknown new
# fields fail closed instead of silently treating new resource-bearing data safe.
_PARENT_FIELDS = {'id','compartment_id','display_name','lifecycle_state','time_created','ip_addresses',
    'shape_name','shape_details','is_private','is_delete_protection_enabled','is_request_id_enabled',
    'request_id_header','subnet_ids','subnet_id','network_security_group_ids','freeform_tags','defined_tags',
    'security_attributes','system_tags','ip_mode','lifecycle_details','nlb_ip_version','time_updated',
    'is_preserve_source_destination','is_symmetric_hash_enabled'} | set(_CONFIG['LoadBalancer'])
_CONFIG_FIELDS = {
    'listeners': {'name','default_backend_set_name','port','protocol','hostname_names','path_route_set_name',
                  'ssl_configuration','connection_configuration','rule_set_names','routing_policy_name'},
    'backend_sets': {'name','policy','backends','backend_max_connections','health_checker','ssl_configuration',
                     'session_persistence_configuration','lb_cookie_session_persistence_configuration'},
    'hostnames': {'name','hostname'}, 'certificates': {'certificate_name','public_certificate','ca_certificate','private_key'},
    'path_route_sets': {'name','path_routes'}, 'rule_sets': {'name','items'},
    'routing_policies': {'name','condition_language_version','rules'}, 'ssl_cipher_suites': {'name','ciphers'},
}
_NLB_FIELDS = {
    'listeners': {'name','default_backend_set_name','port','protocol','ip_version','is_ppv2_enabled',
                  'tcp_idle_timeout','udp_idle_timeout','l3_ip_idle_timeout'},
    'backend_sets': {'name','policy','is_preserve_source','is_fail_open','is_instant_failover_enabled',
                     'is_instant_failover_tcp_reset_enabled','are_operationally_active_backends_preferred',
                     'ip_version','backends','health_checker'},
}
_SSL_FIELDS = {'verify_depth','verify_peer_certificate','has_session_resumption','trusted_certificate_authority_ids',
               'certificate_ids','certificate_name','server_order_preference','cipher_suite_name','protocols'}
_BACKEND_FIELDS = {
    'LoadBalancer': {'name','ip_address','port','weight','max_connections','drain','backup','offline'},
    'NetworkLoadBalancer': {'name','ip_address','target_id','port','weight','is_drain','is_backup','is_offline'},
}
_REFERENCES = ('subnet_ids','subnet_id','network_security_group_ids','certificate_ids',
               'trusted_certificate_authority_ids','reserved_public_ip_ids','backend_target_ids')
_META = _REFERENCES + ('configuration','ip_endpoints','relationship_snapshot','cascade_members','cascade_snapshot',
                      'cascade_owner','cascade_verified','parent_type','configuration_field','configuration_name')


def _strings(value):
    if not isinstance(value,list) or any(not isinstance(v,str) or not v for v in value):
        raise CleanupError('Malformed typed load balancer references')
    if len(set(value)) != len(value):
        raise CleanupError('Duplicate typed load balancer reference')
    return sorted(value)


def _live(gateway,region,kind,key):
    prefix='ocid1.loadbalancer.' if kind=='LoadBalancer' else 'ocid1.networkloadbalancer.'
    if not isinstance(key,str) or not key.startswith(prefix):raise CleanupError('Load balancer OCID type mismatch')
    service,_,operation,_,param = _CONTRACTS[kind]
    row,headers=gateway.read(service,region,operation,{param:key})
    return _identity(row,key),headers


def _configuration(kind,row):
    """Keep only typed association fields and names; never copy certificate PEM."""
    if set(row)-_PARENT_FIELDS:
        raise CleanupError('Unknown parent configuration contract')
    config={};certs=[];cas=[];targets=[]
    for field in _CONFIG[kind]:
        values=row.get(field)
        if values is None:values={}
        if not isinstance(values,dict):raise CleanupError('Unknown owned configuration')
        safe={}
        for name,value in values.items():
            if not isinstance(name,str) or not name or not isinstance(value,dict):
                raise CleanupError('Malformed parent configuration name')
            allowed=(_NLB_FIELDS if kind=='NetworkLoadBalancer' else _CONFIG_FIELDS)[field]
            if set(value)-allowed:raise CleanupError('Unknown owned configuration contract')
            if value.get('id') or value.get('compartment_id'):
                raise CleanupError('Independent resource cannot be parent configuration')
            declared=value.get('certificate_name' if field=='certificates' else 'name')
            if declared is not None and declared!=name:
                raise CleanupError('Conflicting parent configuration identity')
            refs={}
            for key in ('default_backend_set_name','path_route_set_name','routing_policy_name'):
                if value.get(key) is not None:
                    if not isinstance(value[key],str) or not value[key]:raise CleanupError('Unknown configuration association')
                    refs[key]=value[key]
            for key in ('hostname_names','rule_set_names'):
                if value.get(key) is not None:refs[key]=_strings(value[key])
            ssl=value.get('ssl_configuration')
            if ssl is not None:
                if not isinstance(ssl,dict) or set(ssl)-_SSL_FIELDS:raise CleanupError('Unknown TLS association')
                refs['certificate_ids']=_strings(ssl.get('certificate_ids') or [])
                refs['trusted_certificate_authority_ids']=_strings(ssl.get('trusted_certificate_authority_ids') or [])
                certs.extend(refs['certificate_ids']);cas.extend(refs['trusted_certificate_authority_ids'])
                for key in ('certificate_name','cipher_suite_name'):
                    if ssl.get(key):refs[key]=ssl[key]
            if field=='backend_sets':
                backends=value.get('backends')
                if not isinstance(backends,list):raise CleanupError('Unknown backend inventory')
                refs['backends']=[]
                for backend in backends:
                    if (not isinstance(backend,dict) or not isinstance(backend.get('name'),str)
                            or set(backend)-_BACKEND_FIELDS[kind]):raise CleanupError('Unknown backend')
                    safe_backend={k:backend[k] for k in ('name','ip_address','port','target_id') if backend.get(k) is not None}
                    if backend.get('target_id'):
                        if not isinstance(backend['target_id'],str):raise CleanupError('Unknown backend target')
                        targets.append(backend['target_id'])
                    refs['backends'].append(safe_backend)
                refs['backends'].sort(key=lambda b:b['name'])
            safe[name]=refs
        config[field]=safe
    return config,sorted(set(certs)),sorted(set(cas)),sorted(set(targets))


def _snapshot(gateway,kind,row,region,scope):
    config,certs,cas,targets=_configuration(kind,row)
    subnets=_strings(row.get('subnet_ids')) if kind=='LoadBalancer' else _strings([row.get('subnet_id')])
    if not subnets:raise CleanupError('Load balancer has no verified subnet association')
    nsgs=_strings(row.get('network_security_group_ids') or [])
    refs={};issues=[]
    for keys,service,operation,param in ((subnets,'network','get_subnet','subnet_id'),
        (nsgs,'network','get_network_security_group','network_security_group_id'),
        (certs,'certificates','get_certificate','certificate_id'),
        (cas,'certificates','get_certificate_authority','certificate_authority_id')):
        for key in keys:
            read_operation,read_param=operation,param
            if service=='certificates' and param=='certificate_authority_id' and key.startswith('ocid1.cabundle.'):
                read_operation,read_param='get_ca_bundle','ca_bundle_id'
            live,_=gateway.read(service,region,read_operation,{read_param:key});_identity(live,key)
            refs[key]={'compartment_id':live['compartment_id']}
            if live.get('lifecycle_state') in ('DELETED','TERMINATED'):
                raise CleanupError('Reference target is terminal')
    endpoints=row.get('ip_addresses')
    if not isinstance(endpoints,list):raise CleanupError('Unknown load balancer endpoint inventory')
    safe_endpoints=[];reserved=[]
    for endpoint in endpoints:
        if (not isinstance(endpoint,dict) or not isinstance(endpoint.get('ip_address'),str)
                or type(endpoint.get('is_public')) is not bool):raise CleanupError('Unknown service endpoint')
        item={'ip_address':endpoint['ip_address'],'is_public':endpoint['is_public']}
        reserved_ip=endpoint.get('reserved_ip')
        if reserved_ip is not None:
            if not isinstance(reserved_ip,dict) or not isinstance(reserved_ip.get('id'),str):raise CleanupError('Unknown reserved IP identity')
            key=reserved_ip['id'];live,_=gateway.read('network',region,'get_public_ip',{'public_ip_id':key});_identity(live,key)
            if live.get('lifetime')!='RESERVED':raise CleanupError('Reserved public IP lifetime is not proven')
            ref={k:live[k] for k in ('compartment_id','lifetime','private_ip_id','assigned_entity_id','assigned_entity_type') if live.get(k) is not None}
            private=live.get('private_ip_id')
            if live.get('assigned_entity_type')=='PRIVATE_IP':
                if private and private!=live.get('assigned_entity_id'):raise CleanupError('Conflicting public IP assignment')
                private=live.get('assigned_entity_id')
            if private:
                ip,_=gateway.read('network',region,'get_private_ip',{'private_ip_id':private});_identity(ip,private)
                if ip.get('subnet_id') not in subnets or ip['compartment_id'] not in scope or not ip.get('vnic_id'):
                    raise CleanupError('Reserved IP associated private IP is external or unknown')
                vnic,_=gateway.read('network',region,'get_vnic',{'vnic_id':ip['vnic_id']});_identity(vnic,ip['vnic_id'])
                if vnic['compartment_id'] not in scope or vnic.get('subnet_id')!=ip['subnet_id']:
                    raise CleanupError('Associated VNIC scope is unresolved')
                ref['private_ip']={k:ip[k] for k in ('id','compartment_id','vnic_id','subnet_id','route_table_id','lifetime') if ip.get(k) is not None}
                ref['vnic']={k:vnic[k] for k in ('id','compartment_id','subnet_id','nsg_ids','route_table_id') if vnic.get(k) is not None}
            refs[key]=ref;reserved.append(key);item['reserved_public_ip_id']=key
        # The LB service endpoints and implicit VNICs inherit the actual subnet
        # compartment. This proves scope, never the identity of an arbitrary IP.
        if not subnets or any(refs[key]['compartment_id'] not in scope for key in subnets):
            issues.append('Implicit service network child may be outside deletion scope')
        safe_endpoints.append(item)
    # Backend.target_id is documented as an Instance/IP association. DeleteBackend
    # removes this configuration from the backend set (it never terminates Compute
    # or deletes its IP). Read known exact IDs; retain unsupported IDs and block.
    for key in targets:
        if key.startswith('ocid1.instance.'):
            service,operation,param='compute','get_instance','instance_id'
        elif key.startswith('ocid1.privateip.'):
            service,operation,param='network','get_private_ip','private_ip_id'
        else:
            issues.append('Backend target non-cascade contract is unresolved; target IDs retained')
            continue
        target,_=gateway.read(service,region,operation,{param:key});_identity(target,key)
        refs[key]={k:target[k] for k in ('compartment_id','subnet_id','vnic_id') if target.get(k) is not None}
    if row.get('is_delete_protection_enabled') is True:
        issues.append('Load balancer deletion protection is enabled')
    metadata={'configuration':config,'ip_endpoints':safe_endpoints,'network_security_group_ids':nsgs,
              'certificate_ids':certs,'trusted_certificate_authority_ids':cas,
              'reserved_public_ip_ids':sorted(reserved),'backend_target_ids':targets,'relationship_snapshot':refs}
    metadata['subnet_ids' if kind=='LoadBalancer' else 'subnet_id']=subnets if kind=='LoadBalancer' else subnets[0]
    return metadata,issues


def _children(parent):
    children=[]
    for field,values in parent.metadata['configuration'].items():
        for name in sorted(values):
            key=child_key('load-balancer-config',parent.region,parent.key,field+'/'+name)
            children.append(Node(key,'LoadBalancerConfiguration',parent.region,parent.compartment_id,name,
                parent.lifecycle_state,'load_balancers','cascade',{'cascade_owner':parent.key,'cascade_verified':True,
                'parent_type':parent.resource_type,'configuration_field':field,'configuration_name':name}))
    return children


class LoadBalancers(Handler):
    name='load_balancers';action='delete'
    resource_types=tuple(_CONTRACTS)+('LoadBalancerConfiguration',)
    metadata_keys=_META
    retained_reference_fields=_REFERENCES

    def classify(self,node):
        metadata={k:v for k,v in node.metadata.items() if k in self.metadata_keys}
        return replace(node,handler=self.name,action='cascade' if node.resource_type=='LoadBalancerConfiguration' else 'delete',metadata=metadata)

    def _parent(self,gateway,kind,row,region,scope):
        metadata,issues=_snapshot(gateway,kind,row,region,scope)
        parent=Node(row['id'],kind,region,row['compartment_id'],row.get('display_name') or '',row.get('lifecycle_state') or '',self.name,self.action,metadata)
        children=_children(parent)
        parent=replace(parent,metadata=dict(metadata,cascade_members=sorted(n.key for n in children),
            cascade_snapshot={n.key:n.metadata for n in children}))
        for issue in issues:parent=_blocked(parent,issue)
        return parent,children

    def discover(self,gateway,compartment_id,region):
        nodes=[];edges=[];probes=[];scope=_scope(gateway)
        for kind,(service,listing,_,_,_) in _CONTRACTS.items():
            status='complete'
            try:
                seen=set()
                for summary in gateway.items(service,region,listing,{'compartment_id':compartment_id}):
                    _identity(summary,owner=compartment_id)
                    if summary['id'] in seen:raise CleanupError('Duplicate load balancer identity')
                    seen.add(summary['id'])
                    row,_=_live(gateway,region,kind,summary['id']);_identity(row,summary['id'],compartment_id)
                    if row.get('lifecycle_state')=='DELETED':continue
                    try:
                        node,children=self._parent(gateway,kind,row,region,scope)
                        nodes.extend(children)
                        for field in _REFERENCES:
                            values=node.metadata.get(field);values=values if isinstance(values,list) else [values] if values else []
                            for key in values:
                                if node.metadata['relationship_snapshot'].get(key,{}).get('compartment_id') in scope:
                                    edges.append(Edge(node.key,key,'Typed retained load balancer reference: '+field))
                    except Exception:
                        # A denied target GET must not erase known safe outbound IDs.
                        # These declarations do not renew any cascade/scope proof.
                        metadata={}
                        try:
                            config,certs,cas,targets=_configuration(kind,row)
                            metadata={'configuration':config,'certificate_ids':certs,
                                      'trusted_certificate_authority_ids':cas,'backend_target_ids':targets,
                                      'network_security_group_ids':_strings(row.get('network_security_group_ids') or [])}
                            field='subnet_ids' if kind=='LoadBalancer' else 'subnet_id'
                            metadata[field]=_strings(row.get(field)) if kind=='LoadBalancer' else row.get(field)
                        except Exception:pass
                        node=Node(row['id'],kind,region,compartment_id,row.get('display_name') or '',row.get('lifecycle_state') or '',self.name,'unresolved',metadata,('Load balancer ownership or relationships unresolved',))
                    nodes.append(node)
            except Exception:status='failed'
            probes.append(Probe(service,region,compartment_id,status,'Typed load balancer list and exact GET inventory'))
        return nodes,edges,probes

    def inspect(self,gateway,node,scope):
        try:
            if node.resource_type=='LoadBalancerConfiguration':
                owner=node.metadata.get('cascade_owner');kind=node.metadata.get('parent_type')
                if kind not in _CONTRACTS:raise CleanupError('Unknown parent type')
                field=node.metadata.get('configuration_field');name=node.metadata.get('configuration_name')
                if field not in _CONFIG[kind] or node.key!=child_key('load-balancer-config',node.region,owner,field+'/'+name):
                    raise CleanupError('Configuration child identity mismatch')
                row,headers=_live(gateway,node.region,kind,owner)
            else:
                kind=node.resource_type;row,headers=_live(gateway,node.region,kind,node.key)
            compartment=row['compartment_id'];state=row.get('lifecycle_state') or ''
            if compartment!=node.compartment_id or compartment not in scope:
                return Observation('moved',compartment,state,None,None,'Live load balancer ownership changed')
            if state=='DELETED':return Observation('deleted',compartment,state,None,headers.get('etag'),'Positive parent terminal deletion')
            if state=='DELETING':return Observation('pending',compartment,state,None,headers.get('etag'),'Load balancer deletion remains pending')
            if state!='ACTIVE':raise CleanupError('Load balancer is not eligible')
            fresh,children=self._parent(gateway,kind,row,node.region,scope)
            if fresh.blockers:raise CleanupError('Unresolved load balancer relationships')
            if node.resource_type=='LoadBalancerConfiguration':
                if not any(n.key==node.key and n.metadata==node.metadata for n in children):raise CleanupError('Configuration membership changed')
            elif fresh.metadata!=node.metadata:raise CleanupError('Relationships or cascade membership changed')
            return Observation('present',compartment,state,None,headers.get('etag'),'Fresh scope, retained references and parent configuration verified')
        except Exception:return Observation('unresolved',node.compartment_id,'',None,None,'Load balancer identity, scope or relationships unresolved; refresh report')

    def submit(self,gateway,node,observation,attempt_id):
        if node.resource_type not in _CONTRACTS or node.blockers or observation.status!='present' or not observation.etag:
            raise CleanupError('Delete requires an eligible parent and fresh ETag')
        fresh=self.inspect(gateway,node,_scope(gateway))
        if fresh.status!='present' or fresh.etag!=observation.etag:raise CleanupError('Fresh preflight changed')
        service,_,_,operation,param=_CONTRACTS[node.resource_type]
        _,headers=gateway.write(service,node.region,operation,{param:node.key,'if_match':fresh.etag})
        request=headers.get('opc-work-request-id') or headers.get('opc-workrequest-id')
        return Submission('pending',request if isinstance(request,str) and request else None,None,
            'Deletion accepted; exact terminal resource or deletion work request proof required')

    def inspect_work_request(self,gateway,node,request_id,scope):
        """Reconcile a journaled work request using code-defined service contracts.

        Task 9 also reconciles live resource state; historical success never hides
        a newly observed live or moved resource. No artifact selects API methods.
        """
        try:
            if node.resource_type not in _CONTRACTS or node.compartment_id not in scope or not isinstance(request_id,str) or not request_id:
                raise CleanupError('Unknown journaled deletion identity')
            service=_CONTRACTS[node.resource_type][0]
            work,_=gateway.read(service,node.region,'get_work_request',{'work_request_id':request_id})
            _identity(work,request_id,node.compartment_id)
            if node.resource_type=='LoadBalancer':
                if (not node.key.startswith('ocid1.loadbalancer.') or work.get('load_balancer_id')!=node.key
                        or work.get('type')!='DeleteLoadBalancer'):
                    raise CleanupError('Work request is not this exact parent delete')
                state=work.get('lifecycle_state');errors=work.get('error_details')
                if not isinstance(errors,list) or errors:raise CleanupError('Work request errors unresolved')
            else:
                if not node.key.startswith('ocid1.networkloadbalancer.'):
                    raise CleanupError('Work request resource type mismatch')
                if work.get('operation_type')!='DELETE_NETWORK_LOAD_BALANCER':raise CleanupError('Work request operation mismatch')
                state=work.get('status');resources=work.get('resources')
                if not isinstance(resources,list):raise CleanupError('Unknown work request resource inventory')
                if state in ('ACCEPTED','IN_PROGRESS','CANCELING'):
                    return Observation('pending',node.compartment_id,state,None,None,'Work request remains pending')
                # entity_type has no documented closed enum. The typed OCID, exact
                # identifier and delete operation bind identity without guessing it.
                if not any(isinstance(r,dict) and r.get('identifier')==node.key
                    and r.get('action_type')=='DELETED' for r in resources):
                    raise CleanupError('No exact network load balancer deletion result')
                if gateway.items(service,node.region,'list_work_request_errors',{'work_request_id':request_id,'compartment_id':node.compartment_id}):
                    raise CleanupError('Work request contains errors')
            if state=='SUCCEEDED':return Observation('deleted',node.compartment_id,state,None,None,'Exact parent deletion work request succeeded without errors')
            if state in ('ACCEPTED','IN_PROGRESS','CANCELING'):
                return Observation('pending',node.compartment_id,state,None,None,'Work request remains pending')
            raise CleanupError('Work request failed or status is unknown')
        except Exception:return Observation('unresolved',node.compartment_id,'',None,None,'Journaled deletion work request proof is unresolved')
