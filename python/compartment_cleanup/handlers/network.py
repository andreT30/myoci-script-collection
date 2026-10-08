"""VCN networking: typed reverse references and bounded, freshly proved cascades.

Network objects may move independently of their VCN. Every reverse inventory scans
all visible tenancy compartments. This is not an atomic lock on related resources.
DNS cascade contract: Oracle dns_resolver resource documentation and DNS/views.htm.
Endpoints and customer zones remain unsupported; they are never implicitly deleted.
"""
from dataclasses import replace
import oci
from .base import Handler
from .core import _identity, _blocked, _scope, _compartments
from ..model import CleanupError, Node, Edge, Observation, Probe, Submission, child_key

NETWORK_OPERATIONS = {
    'Vcn': ('list_vcns','get_vcn','delete_vcn','vcn_id'),
    'Subnet': ('list_subnets','get_subnet','delete_subnet','subnet_id'),
    'InternetGateway': ('list_internet_gateways','get_internet_gateway','delete_internet_gateway','ig_id'),
    'NatGateway': ('list_nat_gateways','get_nat_gateway','delete_nat_gateway','nat_gateway_id'),
    'ServiceGateway': ('list_service_gateways','get_service_gateway','delete_service_gateway','service_gateway_id'),
    'LocalPeeringGateway': ('list_local_peering_gateways','get_local_peering_gateway','delete_local_peering_gateway','local_peering_gateway_id'),
    'RouteTable': ('list_route_tables','get_route_table','delete_route_table','rt_id'),
    'SecurityList': ('list_security_lists','get_security_list','delete_security_list','security_list_id'),
    'DhcpOptions': ('list_dhcp_options','get_dhcp_options','delete_dhcp_options','dhcp_id'),
    'NetworkSecurityGroup': ('list_network_security_groups','get_network_security_group','delete_network_security_group','network_security_group_id'),
}
_DEFAULTS={'default_route_table_id':'RouteTable','default_security_list_id':'SecurityList','default_dhcp_options_id':'DhcpOptions'}
_GATEWAYS=('InternetGateway','NatGateway','ServiceGateway','LocalPeeringGateway')
_FIELDS={
    'Vcn':tuple(_DEFAULTS),
    'Subnet':('vcn_id','route_table_id','security_list_ids','dhcp_options_id'),
    'RouteTable':('vcn_id','route_rules'),
    'SecurityList':('vcn_id',), 'DhcpOptions':('vcn_id',),
    'NetworkSecurityGroup':('vcn_id',),
    'Resolver':('attached_vcn_id','default_view_id','attached_views','rules','endpoints','is_protected'),
    'View':('is_protected',), 'Zone':('is_protected','view_id','scope'),
}
for _kind in _GATEWAYS:_FIELDS[_kind]=('vcn_id','route_table_id','peer_id') if _kind=='LocalPeeringGateway' else ('vcn_id','route_table_id')
_CASCADE=('cascade_owner','cascade_verified','cascade_members','cascade_snapshot')
_DNS={'Resolver':('get_resolver','resolver_id'),'View':('get_view','view_id'),'Zone':('get_zone','zone_name_or_id')}
_TERMINAL={kind:'TERMINATED' for kind in NETWORK_OPERATIONS}
_TERMINAL.update({kind:'DELETED' for kind in _DNS})


def _metadata(kind,row):return {key:row[key] for key in _FIELDS[kind] if row.get(key) is not None}

def _node(kind,row,region):
    _identity(row)
    return Node(row['id'],kind,region,row['compartment_id'],row.get('display_name') or row.get('name') or '',
                row.get('lifecycle_state') or '', 'network','delete',_metadata(kind,row))

def _read(gateway,region,kind,key):
    if kind in NETWORK_OPERATIONS:
        _,operation,_,parameter=NETWORK_OPERATIONS[kind];service='network';params={parameter:key}
    else:
        operation,parameter=_DNS[kind];service='dns';params={parameter:key,'scope':'PRIVATE'}
    row,headers=gateway.read(service,region,operation,params)
    return _identity(row,key),headers

def _active(kind,row):return row.get('lifecycle_state')!=_TERMINAL.get(kind,'TERMINATED')

def _references(kind,row):
    """Only documented association fields, never generic OCID/text scanning."""
    refs=[]
    fields=('vcn_id','route_table_id','dhcp_options_id','subnet_id')
    for field in fields:
        if row.get(field):refs.append(row[field])
    for field in ('security_list_ids','nsg_ids'):
        values=row.get(field,[])
        if values is None:values=[]
        if not isinstance(values,list) or any(not isinstance(v,str) or not v for v in values):
            raise CleanupError('Malformed typed network references')
        refs.extend(values)
    if kind=='DrgAttachment':
        details=row.get('network_details') or {}
        if not isinstance(details,dict):raise CleanupError('Unsupported DRG network details')
        refs.extend(details[field] for field in ('id','route_table_id') if details.get(field))
    return refs


class _Inventory:
    """One fresh visible-tenancy snapshot, including unsupported consumers."""
    def __init__(self,gateway,region):
        self.g=gateway;self.region=region;self.rows={};self.failures=[];self.vnics={};self.nsg_members={};self.nsg_refs={};self.endpoints={}
        compartments=_compartments(gateway)
        contracts={kind:('network',listing,get,param) for kind,(listing,get,_,param) in NETWORK_OPERATIONS.items()}
        contracts.update({'Vlan':('network','list_vlans','get_vlan','vlan_id'),
            'DrgAttachment':('network','list_drg_attachments','get_drg_attachment','drg_attachment_id'),
            'LoadBalancer':('load_balancer','list_load_balancers','get_load_balancer','load_balancer_id'),
            'NetworkLoadBalancer':('network_load_balancer','list_network_load_balancers','get_network_load_balancer','network_load_balancer_id'),
            'Resolver':('dns','list_resolvers','get_resolver','resolver_id')})
        for kind,(service,listing,get,param) in contracts.items():
            rows=[]
            try:
                for compartment in compartments:
                    params={'compartment_id':compartment}
                    if service=='dns':params['scope']='PRIVATE'
                    for summary in gateway.items(service,region,listing,params):
                        _identity(summary,owner=compartment)
                        if not _active(kind,summary):continue
                        params={param:summary['id']}
                        if service=='dns':params['scope']='PRIVATE'
                        row,_=gateway.read(service,region,get,params)
                        _identity(row,summary['id'],compartment)
                        if kind in _FIELDS and any(row.get(field)!=summary.get(field) for field in _FIELDS[kind]
                                if kind!='Resolver' or field in summary):
                            raise CleanupError('Typed inventory changed between list and GET')
                        if _active(kind,row):rows.append(row)
                if len({row['id'] for row in rows})!=len(rows):raise CleanupError('Duplicate network identity')
                self.rows[kind]=rows
            except Exception:self.failures.append(kind);self.rows[kind]=rows
        try:
            for subnet in self.rows['Subnet']:
                for ip in gateway.items('network',region,'list_private_ips',{'subnet_id':subnet['id']}):
                    _identity(ip)
                    if ip.get('subnet_id')!=subnet['id'] or not ip.get('vnic_id'):
                        raise CleanupError('Private IP subnet membership is unresolved')
                    live,_=gateway.read('network',region,'get_private_ip',{'private_ip_id':ip['id']})
                    _identity(live,ip['id'],ip['compartment_id'])
                    if any(live.get(f)!=ip.get(f) for f in ('subnet_id','vnic_id','route_table_id')):
                        raise CleanupError('Private IP association changed')
                    self._vnic(ip['vnic_id'])
                    self.rows.setdefault('PrivateIp',[]).append(live)
            for compartment in compartments:
                for attachment in gateway.items('compute',region,'list_vnic_attachments',{'compartment_id':compartment}):
                    _identity(attachment,owner=compartment)
                    if attachment.get('lifecycle_state')=='DETACHED':continue
                    if not attachment.get('vnic_id'):raise CleanupError('VNIC association is unresolved')
                    live,_=gateway.read('compute',region,'get_vnic_attachment',{'vnic_attachment_id':attachment['id']})
                    _identity(live,attachment['id'],compartment)
                    if live.get('vnic_id')!=attachment['vnic_id']:raise CleanupError('VNIC attachment changed')
                    self._vnic(attachment['vnic_id'])
            for nsg in self.rows['NetworkSecurityGroup']:
                members=[]
                for member in gateway.items('network',region,'list_network_security_group_vnics',{'network_security_group_id':nsg['id']}):
                    key=member.get('vnic_id')
                    if not key:raise CleanupError('Unknown NSG membership')
                    vnic=self._vnic(key)
                    if nsg['id'] not in (vnic.get('nsg_ids') or []):raise CleanupError('Nonreciprocal NSG membership')
                    members.append(key)
                self.nsg_members[nsg['id']]=members
                rules=gateway.items('network',region,'list_network_security_group_security_rules',{'network_security_group_id':nsg['id']})
                refs=[]
                for rule in rules:
                    for field in ('source','destination'):
                        if rule.get(field+'_type')=='NETWORK_SECURITY_GROUP':
                            if not rule.get(field):raise CleanupError('Unknown NSG rule reference')
                            refs.append(rule[field])
                self.nsg_refs[nsg['id']]=refs
            for resolver in self.rows['Resolver']:
                endpoints=[]
                for summary in gateway.items('dns',region,'list_resolver_endpoints',{'resolver_id':resolver['id'],'scope':'PRIVATE'}):
                    if summary.get('lifecycle_state')=='DELETED':continue
                    if not summary.get('name'):raise CleanupError('Unknown resolver endpoint')
                    live,_=gateway.read('dns',region,'get_resolver_endpoint',{'resolver_id':resolver['id'],'resolver_endpoint_name':summary['name'],'scope':'PRIVATE'})
                    _identity(live,summary.get('id'),resolver['compartment_id'])
                    if live.get('resolver_id')!=resolver['id']:raise CleanupError('Endpoint resolver changed')
                    endpoints.append(live)
                    if live.get('vnic_id'):self._vnic(live['vnic_id'])
                self.endpoints[resolver['id']]=endpoints
        except Exception:self.failures.append('memberships')

    def _vnic(self,key):
        row,_=self.g.read('network',self.region,'get_vnic',{'vnic_id':key});_identity(row,key)
        if _active('Vnic',row):self.vnics[key]=row
        return row

    def consumers(self,key):
        consumers={}
        for kind,rows in self.rows.items():
            for row in rows:
                if row['id']!=key and key in _references(kind,row):consumers[row['id']]=(kind,row)
                if kind=='RouteTable':
                    rules=row.get('route_rules')
                    if not isinstance(rules,list):raise CleanupError('Route inventory is unresolved')
                    if any(rule.get('network_entity_id')==key for rule in rules):consumers[row['id']]=(kind,row)
                if kind=='LoadBalancer' and key in (row.get('subnet_ids') or []):consumers[row['id']]=(kind,row)
        for row in self.vnics.values():
            if key in _references('Vnic',row):consumers[row['id']]=('Vnic',row)
        for nsg,refs in self.nsg_refs.items():
            if nsg!=key and key in refs:consumers[nsg]=('NetworkSecurityGroup',self.find('NetworkSecurityGroup',nsg))
        for resolver,endpoints in self.endpoints.items():
            for row in endpoints:
                if key in _references('ResolverEndpoint',row):consumers[row['id']]=('ResolverEndpoint',row)
        return list(consumers.values())

    def find(self,kind,key):
        rows=[row for row in self.rows.get(kind,[]) if row['id']==key]
        if len(rows)!=1:raise CleanupError('Missing or conflicting typed resource inventory')
        return rows[0]

    def complete(self):
        if self.failures:raise CleanupError('Visible-tenancy network coverage is incomplete')


def _safe_consumers(inventory,key,scope,allow_live):
    inventory.complete();consumers=inventory.consumers(key)
    for kind,row in consumers:
        if row['compartment_id'] not in scope:raise CleanupError('External network consumer')
        if kind not in (*NETWORK_OPERATIONS,'Vnic','PrivateIp'):
            raise CleanupError('Unsupported attached network consumer')
    if consumers and not allow_live:raise CleanupError('Network resource still has live consumers')
    return consumers


def _cascade(gateway,inventory,node,scope):
    inventory.complete();vcn=inventory.find('Vcn',node.key);children=[]
    if vcn['compartment_id'] not in scope:raise CleanupError('VCN cascade owner is external')
    for field,kind in _DEFAULTS.items():
        key=vcn.get(field)
        if not isinstance(key,str) or not key:raise CleanupError('Unknown VCN default identity')
        row=inventory.find(kind,key)
        if row.get('vcn_id')!=node.key or row['compartment_id'] not in scope:
            raise CleanupError('External or nonreciprocal default')
        _safe_consumers(inventory,key,scope,True)
        children.append(_node(kind,row,node.region))
    resolvers=[r for r in inventory.rows['Resolver'] if r.get('attached_vcn_id')==node.key]
    if len(resolvers)!=1:raise CleanupError('Default DNS resolver coverage is unresolved')
    resolver=resolvers[0]
    if (resolver['compartment_id'] not in scope or resolver.get('is_protected') is not True
            or resolver.get('lifecycle_state')!='ACTIVE' or resolver.get('rules') or resolver.get('attached_views')
            or inventory.endpoints.get(resolver['id']) or resolver.get('endpoints')
            or any(not isinstance(resolver.get(field),list) for field in ('rules','attached_views','endpoints'))):
        raise CleanupError('External or configured DNS resolver requires a separate handler')
    view_id=resolver.get('default_view_id')
    if not isinstance(view_id,str) or not view_id:raise CleanupError('Unknown default DNS view')
    view,_=_read(gateway,node.region,'View',view_id)
    if view['compartment_id'] not in scope or view.get('is_protected') is not True or view.get('lifecycle_state')!='ACTIVE':
        raise CleanupError('External or unprotected DNS default view')
    for other in inventory.rows['Resolver']:
        views=other.get('attached_views') or []
        if not isinstance(views,list):raise CleanupError('Unknown resolver view references')
        if other['id']!=resolver['id'] and (other.get('default_view_id')==view_id or any(v.get('view_id')==view_id for v in views)):
            raise CleanupError('Shared default DNS view')
    children.extend((_node('Resolver',resolver,node.region),_node('View',view,node.region)))
    for compartment in _compartments(gateway):
        for summary in gateway.items('dns',node.region,'list_zones',{'compartment_id':compartment,'view_id':view_id,'scope':'PRIVATE'}):
            _identity(summary,owner=compartment)
            if summary.get('lifecycle_state')=='DELETED':continue
            zone,_=_read(gateway,node.region,'Zone',summary['id']);_identity(zone,summary['id'],compartment)
            if (zone['compartment_id'] not in scope or zone.get('view_id')!=view_id or zone.get('scope')!='PRIVATE'
                    or zone.get('is_protected') is not True or zone.get('lifecycle_state')!='ACTIVE'):
                raise CleanupError('External or customer DNS zone is unsupported')
            children.append(_node('Zone',zone,node.region))
    keys=[child.key for child in children]
    if len(set(keys))!=len(keys):raise CleanupError('Duplicate cascade identity')
    snapshot={child.key:{'resource_type':child.resource_type,'compartment_id':child.compartment_id,'references':child.metadata} for child in children}
    owner=replace(node,metadata=dict(node.metadata,cascade_members=sorted(keys),cascade_snapshot=snapshot))
    children=[replace(child,action='cascade',metadata=dict(child.metadata,cascade_owner=node.key,cascade_verified=True)) for child in children]
    return owner,children


class Networks(Handler):
    name='network';action='delete'
    resource_types=tuple(NETWORK_OPERATIONS)+tuple(_DNS)
    metadata_keys=tuple(sorted({f for fields in _FIELDS.values() for f in fields}|set(_CASCADE)))
    # Deleting a consumer never deletes the VCN or its peering partner.
    retained_reference_fields=('vcn_id','peer_id')

    def classify(self,node):
        metadata={key:value for key,value in node.metadata.items() if key in _FIELDS[node.resource_type] or key in _CASCADE}
        action='cascade' if metadata.get('cascade_owner') else 'unresolved' if node.resource_type in _DNS else 'delete'
        return replace(node,handler=self.name,action=action,metadata=metadata)

    def discover(self,gateway,compartment_id,region):
        scope=_scope(gateway);inventory=_Inventory(gateway,region);nodes={};edges=[]
        probes=[Probe('network:'+kind,region,compartment_id,'failed' if kind in inventory.failures else 'complete','Visible-tenancy typed inventory') for kind in (*NETWORK_OPERATIONS,'Vlan','DrgAttachment','LoadBalancer','NetworkLoadBalancer','Resolver','memberships')]
        for kind in NETWORK_OPERATIONS:
            for row in inventory.rows[kind]:
                if row['compartment_id']!=compartment_id:continue
                node=_node(kind,row,region)
                try:
                    consumers=_safe_consumers(inventory,node.key,scope,True)
                    for consumer_kind,consumer in consumers:
                        if consumer_kind=='RouteTable' and kind in _GATEWAYS:continue
                        edges.append(Edge(consumer['id'],node.key,'Typed reverse network association'))
                    if kind=='Subnet':
                        _cascade(gateway,inventory,_node('Vcn',inventory.find('Vcn',row.get('vcn_id')),region),scope)
                    if kind=='Vcn':
                        node,children=_cascade(gateway,inventory,node,scope)
                        for child in children:
                            # Each compartment discovery emits its own defaults;
                            # fresh owner proof classifies them below too.
                            nodes[child.key]=child
                    elif kind in _DEFAULTS.values():
                        owners=[v for v in inventory.rows['Vcn'] if any(v.get(f)==node.key for f,k in _DEFAULTS.items() if k==kind)]
                        if owners:
                            owner,children=_cascade(gateway,inventory,_node('Vcn',owners[0],region),scope)
                            node=next(child for child in children if child.key==node.key)
                except Exception:node=_blocked(node,'External, unsupported, or unresolved network relationship')
                # Do not overwrite reciprocal DNS/default metadata from the VCN.
                nodes[node.key]=node
        for row in inventory.rows['RouteTable']:
            if row['compartment_id']!=compartment_id:continue
            rules=row.get('route_rules') or []
            gateways={rule.get('network_entity_id') for rule in rules} & {r['id'] for kind in _GATEWAYS for r in inventory.rows[kind] if r['compartment_id'] in scope}
            if not gateways:continue
            prep=_preparation(row,region)
            try:_safe_consumers(inventory,row['id'],scope,True);_validate_routes(gateway,inventory,row,scope)
            except Exception:prep=_blocked(prep,'Route preparation scope or affected associations are unresolved')
            nodes[prep.key]=prep
            edges.append(Edge(prep.key,row['id'],'Route clearing precedes table cleanup'))
            for key in gateways:edges.append(Edge(prep.key,key,'Route clearing precedes gateway cleanup'))
        # Unknown attached types remain visible blockers when they belong here.
        for kind in ('Vlan','DrgAttachment'):
            for row in inventory.rows[kind]:
                if row['compartment_id']==compartment_id:
                    nodes[row['id']]=Node(row['id'],kind,region,compartment_id,row.get('display_name') or '',row.get('lifecycle_state') or '', '', 'unresolved',{},('Unsupported network resource',))
                    for target in _references(kind,row):edges.append(Edge(row['id'],target,'Unsupported typed network association'))
        return list(nodes.values()),edges,probes

    def inspect(self,gateway,node,scope):
        try:
            row,headers=_read(gateway,node.region,node.resource_type,node.key);owner=row['compartment_id'];state=row.get('lifecycle_state') or ''
            if owner!=node.compartment_id or owner not in scope:return Observation('moved',owner,state,None,None,'Live owning compartment changed; refresh report')
            if state==_TERMINAL[node.resource_type]:return Observation('deleted',owner,state,None,headers.get('etag'),'Positive typed terminal observation')
            if state in ('TERMINATING','DELETING'):return Observation('pending',owner,state,None,headers.get('etag'),'Deletion remains pending')
            if state!=('ACTIVE' if node.resource_type in _DNS else 'AVAILABLE'):raise CleanupError('Lifecycle is not eligible')
            if _metadata(node.resource_type,row)!={k:v for k,v in node.metadata.items() if k in _FIELDS[node.resource_type]}:raise CleanupError('Typed references changed; refresh report')
            inventory=_Inventory(gateway,node.region);inventory.complete()
            if node.resource_type=='Vcn' or node.metadata.get('cascade_owner'):
                owner_node=node if node.resource_type=='Vcn' else _node('Vcn',inventory.find('Vcn',node.metadata['cascade_owner']),node.region)
                if owner_node.compartment_id not in scope:raise CleanupError('Cascade owner is outside scope')
                fresh,children=_cascade(gateway,inventory,owner_node,scope)
                if node.resource_type=='Vcn':
                    if fresh.metadata.get('cascade_snapshot')!=node.metadata.get('cascade_snapshot') or fresh.metadata.get('cascade_members')!=node.metadata.get('cascade_members'):raise CleanupError('Cascade changed; refresh report')
                    consumers=_safe_consumers(inventory,node.key,scope,True)
                    allowed=set(fresh.metadata['cascade_members'])
                    if any(row['id'] not in allowed for _,row in consumers):raise CleanupError('VCN still contains live resources')
                    for child in children:
                        if inventory.consumers(child.key):raise CleanupError('Default still has live consumers')
                        if child.resource_type=='RouteTable' and child.metadata.get('route_rules'):raise CleanupError('Default routes require preparation')
                elif not any(child.key==node.key and child.resource_type==node.resource_type for child in children):raise CleanupError('Fresh reciprocal cascade membership unavailable')
            else:
                if node.resource_type=='Subnet':
                    _cascade(gateway,inventory,_node('Vcn',inventory.find('Vcn',row.get('vcn_id')),node.region),scope)
                if node.resource_type in _DEFAULTS.values() and any(v.get(f)==node.key for v in inventory.rows['Vcn'] for f in _DEFAULTS):raise CleanupError('Default cannot be independently deleted')
                _safe_consumers(inventory,node.key,scope,False)
            return Observation('present',owner,state,None,headers.get('etag'),'Fresh identity, ownership and typed associations')
        except Exception:return Observation('unresolved',node.compartment_id,'',None,None,'Live scope, identity or network relationships unresolved; refresh report')

    def submit(self,gateway,node,observation,attempt_id):
        if observation.status!='present' or not observation.etag:raise CleanupError('Mutation requires eligible live observation and ETag')
        fresh=self.inspect(gateway,node,_scope(gateway))
        if fresh.status!='present' or fresh.etag!=observation.etag:raise CleanupError('Fresh preflight changed')
        if node.resource_type not in NETWORK_OPERATIONS or node.metadata.get('cascade_owner'):raise CleanupError('Cascade objects cannot be independently mutated')
        _,_,operation,parameter=NETWORK_OPERATIONS[node.resource_type]
        _,headers=gateway.write('network',node.region,operation,{parameter:node.key,'if_match':fresh.etag})
        return Submission('pending',headers.get('opc-request-id'),None,'Deletion accepted; positive terminal verification required')


def _preparation(row,region):
    return Node(child_key('network-routes',region,row['id'],'clear'), 'RouteTablePreparation',region,row['compartment_id'],
                'Clear route rules',row.get('lifecycle_state') or '', 'network_routes','prepare',
                {'route_table_id':row['id'],'vcn_id':row.get('vcn_id'),'route_rules':row.get('route_rules')})

def _validate_routes(gateway,inventory,row,scope):
    rules=row.get('route_rules')
    if not isinstance(rules,list):raise CleanupError('Unknown route rules')
    for rule in rules:
        if not isinstance(rule,dict) or not rule.get('network_entity_id'):raise CleanupError('Unknown route entity')
        target=rule['network_entity_id'];matches=[r for kind in _GATEWAYS for r in inventory.rows[kind] if r['id']==target]
        if len(matches)==1:
            if matches[0]['compartment_id'] not in scope:raise CleanupError('External route entity')
            continue
        ip,_=gateway.read('network',inventory.region,'get_private_ip',{'private_ip_id':target});_identity(ip,target)
        if ip['compartment_id'] not in scope:raise CleanupError('External private IP route target')
        # A private IP route target can survive deletion of this table, but the
        # wholesale preparation still requires an in-scope known affected entity.


class RoutePreparations(Handler):
    name='network_routes';action='prepare';resource_types=('RouteTablePreparation',)
    metadata_keys=('route_table_id','vcn_id','route_rules')
    retained_reference_fields=('vcn_id',)
    def discover(self,gateway,compartment_id,region):
        return [],[],[Probe(self.name,region,compartment_id,'complete','Preparation nodes are emitted by typed network discovery')]
    def inspect(self,gateway,node,scope):
        try:
            key=node.metadata.get('route_table_id')
            if node.key!=child_key('network-routes',node.region,key,'clear'):raise CleanupError('Preparation identity changed')
            row,headers=_read(gateway,node.region,'RouteTable',key);owner=row['compartment_id'];state=row.get('lifecycle_state') or ''
            if owner!=node.compartment_id or owner not in scope:return Observation('moved',owner,state,None,None,'Route table owner changed')
            if state!='AVAILABLE':raise CleanupError('Route table is not eligible')
            if row.get('vcn_id')!=node.metadata.get('vcn_id'):raise CleanupError('VCN association changed')
            inventory=_Inventory(gateway,node.region)
            _safe_consumers(inventory,key,scope,True)
            if not row.get('route_rules'):return Observation('deleted',owner,state,None,headers.get('etag'),'Planned route preparation is positively complete; the route table persists')
            if row.get('route_rules')!=node.metadata.get('route_rules'):raise CleanupError('Routes changed; refresh report')
            _validate_routes(gateway,inventory,row,scope)
            return Observation('present',owner,state,None,headers.get('etag'),'All affected live route associations verified in scope')
        except Exception:return Observation('unresolved',node.compartment_id,'',None,None,'Route preparation scope, identity or associations unresolved')
    def submit(self,gateway,node,observation,attempt_id):
        if observation.status!='present' or not observation.etag:raise CleanupError('Preparation requires fresh eligible ETag')
        fresh=self.inspect(gateway,node,_scope(gateway))
        if fresh.status!='present' or fresh.etag!=observation.etag:raise CleanupError('Preparation preflight changed')
        _,headers=gateway.write('network',node.region,'update_route_table',{'rt_id':node.metadata['route_table_id'],
            'update_route_table_details':oci.core.models.UpdateRouteTableDetails(route_rules=[]),'if_match':fresh.etag})
        return Submission('pending',headers.get('opc-request-id'),None,'Route update accepted; verify empty rules and reconcile this known preparation transition')
