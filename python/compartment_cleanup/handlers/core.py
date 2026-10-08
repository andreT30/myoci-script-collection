"""IAM, Compute and Block Storage contracts with live scope and dependency proof.

All association scans use the visible tenancy hierarchy, separately from the
validated deletion boundary. Scope snapshots are not atomic service transactions:
owner ETags cannot lock associated objects against concurrent movement.
"""
from dataclasses import replace

from .base import Handler
from ..model import CleanupError, Node, Edge, Observation, Probe, Submission
from ..gateway import GatewayError


_POLICY = {'Policy': ('identity', 'list_policies', 'get_policy', 'delete_policy', 'policy_id')}
_COMPUTE = {
    'Instance': ('compute', 'list_instances', 'get_instance', 'terminate_instance', 'instance_id'),
    'VnicAttachment': ('compute', 'list_vnic_attachments', 'get_vnic_attachment', None, 'vnic_attachment_id'),
    'VolumeAttachment': ('compute', 'list_volume_attachments', 'get_volume_attachment', 'detach_volume', 'volume_attachment_id'),
    'BootVolumeAttachment': ('compute', 'list_boot_volume_attachments', 'get_boot_volume_attachment', 'detach_boot_volume', 'boot_volume_attachment_id'),
    'Vnic': ('network', None, 'get_vnic', None, 'vnic_id'),
    'PrivateIp': ('network', None, 'get_private_ip', None, 'private_ip_id'),
    'PublicIp': ('network', None, 'get_public_ip', None, 'public_ip_id'),
}
_VOLUMES = {
    'Volume': ('blockstorage', 'list_volumes', 'get_volume', 'delete_volume', 'volume_id'),
    'BootVolume': ('blockstorage', 'list_boot_volumes', 'get_boot_volume', 'delete_boot_volume', 'boot_volume_id'),
    'VolumeBackup': ('blockstorage', 'list_volume_backups', 'get_volume_backup', 'delete_volume_backup', 'volume_backup_id'),
    'BootVolumeBackup': ('blockstorage', 'list_boot_volume_backups', 'get_boot_volume_backup', 'delete_boot_volume_backup', 'boot_volume_backup_id'),
}
_FIELDS = {
    'Policy': (),
    'Instance': ('availability_domain', 'instance_configuration_id'),
    'VnicAttachment': ('instance_id', 'vnic_id', 'availability_domain'),
    'VolumeAttachment': ('instance_id', 'volume_id', 'attachment_type', 'availability_domain'),
    'BootVolumeAttachment': ('instance_id', 'boot_volume_id', 'availability_domain'),
    'Vnic': ('subnet_id', 'vlan_id', 'nsg_ids', 'route_table_id', 'ipv6_addresses', 'private_ip', 'public_ip'),
    'PrivateIp': ('vnic_id', 'subnet_id', 'vlan_id', 'route_table_id', 'lifetime', 'ip_state', 'ip_address', 'is_primary'),
    'PublicIp': ('private_ip_id', 'assigned_entity_id', 'assigned_entity_type', 'lifetime', 'scope', 'availability_domain', 'ip_address'),
}
_VOLUME_FIELDS = ('kms_key_id', 'volume_group_id', 'volume_group_backup_id',
                  'block_volume_replicas', 'boot_volume_replicas',
                  'is_prevent_deletion_enabled', 'is_retention_lock_enabled',
                  'is_indefinite_retention_enabled', 'time_retention_expires_at', 'retention_period')
for _kind in _VOLUMES:
    _FIELDS[_kind] = _VOLUME_FIELDS
_CASCADE = ('cascade_owner', 'cascade_members', 'cascade_verified', 'cascade_references', 'cascade_snapshot', 'retained_public_ips', 'preserved_volume_ids')


def _identity(row, key=None, owner=None):
    if (type(row) is not dict or not isinstance(row.get('id'), str) or not row['id']
            or not isinstance(row.get('compartment_id'), str) or not row['compartment_id']
            or (key is not None and row['id'] != key)
            or (owner is not None and row['compartment_id'] != owner)):
        raise CleanupError('Live resource identity or owning compartment changed')
    return row


def _metadata(kind, row):
    return {key: row[key] for key in _FIELDS[kind] if row.get(key) is not None}


def _node(kind, row, region, handler):
    _identity(row)
    return Node(row['id'], kind, region, row['compartment_id'], row.get('display_name') or '',
                row.get('lifecycle_state') or '', handler.name, handler.action, _metadata(kind,row))


def _blocked(node, reason):
    return replace(node, action='unresolved', blockers=tuple(sorted(set(node.blockers + (reason,)))))


def _scope(gateway):
    scope = getattr(gateway, 'cleanup_scope', None)
    if not isinstance(scope, set) or not scope:
        raise CleanupError('Validated deletion scope is unavailable')
    return scope


def _compartments(gateway):
    if not gateway.tenancy_id or not gateway.compartment_links:
        raise CleanupError('Full tenancy compartment hierarchy is unavailable')
    return sorted({gateway.tenancy_id, *gateway.compartment_links})


def _ads(gateway, region):
    rows = gateway.items('identity', region, 'list_availability_domains', {'compartment_id':gateway.tenancy_id})
    names = [row.get('name') for row in rows]
    if not names or any(not isinstance(name,str) or not name for name in names) or len(set(names)) != len(names):
        raise CleanupError('Availability domain inventory is incomplete')
    return names


def _attachments(gateway, region, kinds=('VnicAttachment','VolumeAttachment','BootVolumeAttachment')):
    """Boot volumes can also be attached as data volumes; enumerate both families."""
    result = []
    domains = _ads(gateway,region)
    for compartment in _compartments(gateway):
        for kind in kinds:
            service, listing, _, _, _ = _COMPUTE[kind]
            for domain in domains if kind == 'BootVolumeAttachment' else [None]:
                params = {'compartment_id':compartment}
                if domain:
                    params['availability_domain'] = domain
                for row in gateway.items(service,region,listing,params):
                    _identity(row, owner=compartment)
                    if not row.get('instance_id'):
                        raise CleanupError('Attachment has no typed instance association')
                    if kind == 'BootVolumeAttachment' and row.get('availability_domain') != domain:
                        raise CleanupError('Boot attachment availability domain changed')
                    result.append((kind,row))
    identities = [row['id'] for _,row in result]
    if len(set(identities)) != len(identities):
        raise CleanupError('Conflicting attachment inventory')
    return result


def _read(gateway, region, kind, key):
    service, _, operation, _, parameter = {**_POLICY, **_COMPUTE, **_VOLUMES}[kind]
    row, headers = gateway.read(service,region,operation,{parameter:key})
    return _identity(row,key), headers


def _instance_endpoint(gateway,region,attachment,scope):
    row,_ = _read(gateway,region,'Instance',attachment['instance_id'])
    if row['compartment_id'] not in scope:
        raise CleanupError('Attachment instance is outside the deletion boundary')
    return row


class _TypedHandler(Handler):
    """Fixed dispatch, fresh ownership and type-specific positive terminal evidence."""
    action = 'delete'
    contracts = {}
    terminal = {}
    eligible = {}
    # No bulk catalog alias is enabled without exact supported catalog evidence.
    bulk_resource_types = {}

    def classify(self,node):
        metadata = {key:value for key,value in node.metadata.items()
                    if key in _FIELDS[node.resource_type] or key in _CASCADE}
        node = replace(node,handler=self.name,action=self.action,metadata=metadata)
        if node.resource_type in ('Vnic','PrivateIp','PublicIp','VnicAttachment'):
            return replace(node,action='cascade' if metadata.get('cascade_owner') else 'unresolved')
        if node.resource_type in ('VolumeAttachment','BootVolumeAttachment'):
            return replace(node,action='cascade' if metadata.get('cascade_owner') else 'prepare')
        return node

    def _live(self,gateway,node,scope):
        if node.resource_type not in self.contracts:
            raise CleanupError('Unsupported typed resource')
        row,headers = _read(gateway,node.region,node.resource_type,node.key)
        owner = row['compartment_id']
        state = row.get('lifecycle_state') or ''
        if owner not in scope or owner != node.compartment_id:
            return row,Observation('moved',owner,state,None,None,'Live ownership changed; refresh report')
        if state == self.terminal.get(node.resource_type):
            return row,Observation('deleted',owner,state,None,headers.get('etag'),'Positive terminal resource observation')
        if state in ('TERMINATING','DELETING','DETACHING'):
            return row,Observation('pending',owner,state,None,headers.get('etag'),'Service deletion remains pending')
        if any(row.get(field) != node.metadata.get(field) for field in _FIELDS[node.resource_type]):
            raise CleanupError('Typed dependency changed; refresh report')
        if node.resource_type != 'PrivateIp' and state not in self.eligible.get(node.resource_type,()):
            raise CleanupError('Lifecycle state does not establish deletion eligibility')
        return row,Observation('present',owner,state,None,headers.get('etag'),'Fresh typed identity and ownership')

    def inspect(self,gateway,node,scope):
        try:
            row,observation = self._live(gateway,node,scope)
            if observation.status == 'present':
                self._dependencies(gateway,node,row,scope)
            return observation
        except Exception:
            return Observation('unresolved',node.compartment_id,'',None,None,
                               'Live identity, scope, or dependencies are unresolved; refresh report')

    def submit(self,gateway,node,observation,attempt_id):
        # A fabricated or stale artifact/Observation cannot authorize a mutation.
        if observation.status != 'present' or not observation.etag:
            raise CleanupError('Mutation requires a fresh eligible observation and ETag')
        scope = _scope(gateway)
        fresh = self.inspect(gateway,node,scope)
        if fresh.status != 'present' or fresh.etag != observation.etag:
            raise CleanupError('Preflight identity, scope, dependencies or ETag changed')
        service,_,_,operation,parameter = self.contracts[node.resource_type]
        if not operation or node.metadata.get('cascade_owner'):
            raise CleanupError('Cascade members cannot be mutated independently')
        params = {parameter:node.key,'if_match':fresh.etag}
        if node.resource_type == 'Instance':
            params.update(preserve_boot_volume=True,preserve_data_volumes_created_at_launch=True)
        _,headers = gateway.write(service,node.region,operation,params)
        return Submission('pending',headers.get('opc-request-id'),None,'Operation accepted; terminal verification required')

    def _dependencies(self,gateway,node,row,scope):
        pass


class IAMPolicies(_TypedHandler):
    name = 'policies'
    resource_types = tuple(_POLICY)
    contracts = _POLICY
    metadata_keys = ()
    terminal = {'Policy':'DELETED'}
    eligible = {'Policy':('ACTIVE',)}
    late_action = True

    def discover(self,gateway,compartment_id,region):
        if region != gateway.home_region:
            return [],[],[Probe(self.name,region,compartment_id,'complete','Home-region policy inventory only')]
        nodes = [_node('Policy',_identity(row,owner=compartment_id),region,self)
                 for row in gateway.items('identity',region,'list_policies',{'compartment_id':compartment_id})]
        return nodes,[],[Probe(self.name,region,compartment_id,'complete','')]


class BlockBootVolumes(_TypedHandler):
    name = 'blockstorage'
    resource_types = tuple(_VOLUMES)
    contracts = _VOLUMES
    metadata_keys = _VOLUME_FIELDS
    # Encryption keys survive consumer deletion; source backups are lineage.
    retained_reference_fields = ('kms_key_id',)
    terminal = {kind:'TERMINATED' for kind in _VOLUMES}
    eligible = {kind:('AVAILABLE',) for kind in _VOLUMES}

    def corroborate_bulk_absence(self,gateway,node,scope):
        """Only a caller's exact positive bulk DELETED evidence enables this path.

        Complete typed regional inventories corroborate that event; absence by
        itself is never positive deletion evidence. Scan visible tenancy links
        so live ownership movement cannot be hidden by a scoped inventory.
        """
        try:
            if node.resource_type not in _VOLUMES or node.compartment_id not in scope:
                return False
            try:
                live,_=_read(gateway,node.region,node.resource_type,node.key)
                if live['compartment_id']!=node.compartment_id or live.get('lifecycle_state')!=self.terminal[node.resource_type]:return False
            except GatewayError as error:
                if error.status!=404:return False
            if node.resource_type in ('Volume','BootVolume') and self._connections(gateway,node,scope):return False
            service,listing,_,_,_=_VOLUMES[node.resource_type]
            seen=set()
            for compartment in _compartments(gateway):
                for row in gateway.items(service,node.region,listing,{'compartment_id':compartment}):
                    _identity(row,owner=compartment)
                    if row['id'] in seen:raise CleanupError('Conflicting typed inventory')
                    seen.add(row['id'])
                    if row['id']==node.key and (row['compartment_id']!=node.compartment_id or row.get('lifecycle_state')!=self.terminal[node.resource_type]):
                        return False
            return True
        except Exception:return False

    def _guards(self,row):
        if any(row.get(field) for field in ('volume_group_id','volume_group_backup_id',
                'block_volume_replicas','boot_volume_replicas','is_prevent_deletion_enabled',
                'is_retention_lock_enabled','is_indefinite_retention_enabled',
                'time_retention_expires_at','retention_period')):
            raise CleanupError('Group, replica, or retention dependency is unsupported')

    def _connections(self,gateway,node,scope):
        matches=[]
        for kind,summary in _attachments(gateway,node.region,('VolumeAttachment','BootVolumeAttachment')):
            field = 'boot_volume_id' if kind=='BootVolumeAttachment' else 'volume_id'
            if summary.get(field) != node.key or summary.get('lifecycle_state')=='DETACHED':
                continue
            row,_ = _read(gateway,node.region,kind,summary['id'])
            _identity(row,summary['id'],summary['compartment_id'])
            if row.get(field) != node.key or row.get('instance_id') != summary.get('instance_id'):
                raise CleanupError('Attachment association changed during inventory')
            if row['compartment_id'] not in scope:
                raise CleanupError('External attachment blocks volume deletion')
            _instance_endpoint(gateway,node.region,row,scope)
            matches.append(row)
        return matches

    def _dependencies(self,gateway,node,row,scope):
        self._guards(row)
        if node.resource_type in ('Volume','BootVolume') and self._connections(gateway,node,scope):
            raise CleanupError('Volume still has live attachments')

    def discover(self,gateway,compartment_id,region):
        nodes,edges,probes=[],[],[]
        scope=_scope(gateway)
        for kind,(service,listing,_,_,_) in self.contracts.items():
            try:
                rows=gateway.items(service,region,listing,{'compartment_id':compartment_id})
                for row in rows:
                    n=_node(kind,_identity(row,owner=compartment_id),region,self)
                    try:
                        live,_=_read(gateway,region,kind,n.key)
                        _identity(live,n.key,compartment_id)
                        if _metadata(kind,live) != n.metadata:
                            raise CleanupError('Volume changed during discovery')
                        self._guards(live)
                        if kind in ('Volume','BootVolume'):
                            for attachment in self._connections(gateway,n,scope):
                                edges.append(Edge(attachment['id'],n.key,'Typed volume attachment'))
                    except Exception:
                        n=_blocked(n,'External, unreadable, grouped, replicated, or protected volume dependency')
                    nodes.append(n)
                probes.append(Probe(self.name+':'+kind,region,compartment_id,'complete',''))
            except Exception:
                probes.append(Probe(self.name+':'+kind,region,compartment_id,'failed','Service inventory failed'))
        return nodes,edges,probes


class ComputeInstances(_TypedHandler):
    name = 'compute'
    resource_types = tuple(_COMPUTE)
    contracts = _COMPUTE
    metadata_keys = tuple(sorted({field for kind in _COMPUTE for field in _FIELDS[kind]} | set(_CASCADE)))
    terminal = {kind:('DETACHED' if kind.endswith('Attachment') else 'TERMINATED') for kind in _COMPUTE if kind!='PrivateIp'}
    eligible = {'Instance':('RUNNING','STOPPED'), 'VnicAttachment':('ATTACHED',),
                'VolumeAttachment':('ATTACHED',), 'BootVolumeAttachment':('ATTACHED',),
                'Vnic':('AVAILABLE',), 'PublicIp':('ASSIGNED',)}

    def _producers(self,gateway,region):
        members,unsupported={},[]
        for compartment in _compartments(gateway):
            for row in gateway.items('compute_management',region,'list_instance_pools',{'compartment_id':compartment}):
                _identity(row,owner=compartment)
                if row.get('lifecycle_state')!='TERMINATED':
                    unsupported.append(('InstancePool',row))
                for member in gateway.items('compute_management',region,'list_instance_pool_instances',
                        {'compartment_id':compartment,'instance_pool_id':row['id']}):
                    if not member.get('id') or member.get('instance_pool_id') != row['id']:
                        raise CleanupError('Instance pool membership is unresolved')
                    members[member['id']] = row['id']
            for row in gateway.items('container_engine',region,'list_clusters',{'compartment_id':compartment}):
                _identity(row,owner=compartment)
                if row.get('lifecycle_state')!='DELETED':
                    unsupported.append(('Cluster',row))
            for row in gateway.items('container_engine',region,'list_node_pools',{'compartment_id':compartment}):
                _identity(row,owner=compartment)
                pool,_=gateway.read('container_engine',region,'get_node_pool',{'node_pool_id':row['id']})
                _identity(pool,row['id'],compartment)
                if pool.get('lifecycle_state')!='DELETED':
                    unsupported.append(('NodePool',pool))
                if not isinstance(pool.get('nodes'),list):
                    raise CleanupError('OKE node pool membership is unresolved')
                for member in pool['nodes']:
                    if not member.get('id') or member.get('node_pool_id')!=pool['id']:
                        raise CleanupError('OKE instance membership is unresolved')
                    members[member['id']]=pool['id']
        return members,unsupported

    def _public_ips(self,gateway,region):
        rows=[]
        domains=_ads(gateway,region)
        for compartment in _compartments(gateway):
            calls=[{'scope':'REGION','compartment_id':compartment,'lifetime':'RESERVED'}]
            calls.extend({'scope':'AVAILABILITY_DOMAIN','compartment_id':compartment,
                          'lifetime':'EPHEMERAL','availability_domain':domain} for domain in domains)
            for params in calls:
                for row in gateway.items('network',region,'list_public_ips',params):
                    _identity(row,owner=compartment)
                    if row.get('scope')!=params['scope'] or row.get('lifetime')!=params['lifetime']:
                        raise CleanupError('Public IP inventory has inconsistent lifetime or scope')
                    rows.append(row)
        return rows

    def _cascade(self,gateway,node,scope,attachments,public_ips):
        children,edges=[],[]
        retained_public_ips,preserved_volume_ids=[],[]
        for kind,summary in attachments:
            if summary['instance_id'] != node.key or summary.get('lifecycle_state')=='DETACHED':
                continue
            row,_ = _read(gateway,node.region,kind,summary['id'])
            _identity(row,summary['id'],summary['compartment_id'])
            if _metadata(kind,row)!=_metadata(kind,summary) or row.get('lifecycle_state')!='ATTACHED':
                raise CleanupError('Attachment membership changed or is transitional')
            if row['compartment_id'] not in scope:
                raise CleanupError('External attachment prevents safe instance termination')
            child=_node(kind,row,node.region,self)
            children.append(child)
            if kind=='VnicAttachment':
                vnic,_=_read(gateway,node.region,'Vnic',row['vnic_id'])
                if vnic['compartment_id'] not in scope:
                    raise CleanupError('External VNIC would be deleted on termination')
                if vnic.get('lifecycle_state')!='AVAILABLE' or vnic.get('vlan_id') or vnic.get('ipv6_addresses'):
                    raise CleanupError('VNIC VLAN or IPv6 cascade coverage is unsupported')
                if not vnic.get('subnet_id'):
                    raise CleanupError('VNIC has no supported subnet association')
                if gateway.items('network',node.region,'list_ipv6s',{'vnic_id':vnic['id']}):
                    raise CleanupError('IPv6 cascade coverage is unsupported')
                nic=_node('Vnic',vnic,node.region,self)
                children.append(nic)
                for field in ('subnet_id','route_table_id','nsg_ids'):
                    targets=vnic.get(field) or []
                    targets=targets if isinstance(targets,list) else [targets]
                    edges.extend(Edge(node.key,target,'Typed VNIC '+field) for target in targets)
                primary_private_ips,primary_public_ips=[],[]
                for summary_ip in gateway.items('network',node.region,'list_private_ips',{'vnic_id':vnic['id']}):
                    ip,_=_read(gateway,node.region,'PrivateIp',summary_ip['id'])
                    _identity(ip,summary_ip['id'],summary_ip['compartment_id'])
                    if (ip['compartment_id'] not in scope or ip.get('vnic_id')!=vnic['id'] or ip.get('vlan_id')
                            or ip.get('subnet_id')!=vnic.get('subnet_id')
                            or ip.get('lifetime')!='EPHEMERAL' or ip.get('ip_state')!='ASSIGNED'):
                        raise CleanupError('Private IP cascade scope is unresolved')
                    if _metadata('PrivateIp',ip)!=_metadata('PrivateIp',summary_ip):
                        raise CleanupError('Private IP dependency changed')
                    if not isinstance(ip.get('ip_address'),str) or not ip['ip_address'] or type(ip.get('is_primary')) is not bool:
                        raise CleanupError('Private IP address or primary membership is unresolved')
                    if ip['is_primary']:
                        primary_private_ips.append(ip)
                    children.append(_node('PrivateIp',ip,node.region,self))
                    if ip.get('route_table_id'):
                        edges.append(Edge(node.key,ip['route_table_id'],'Typed private IP route table'))
                    for summary_public in public_ips:
                        if ip['id'] not in (summary_public.get('private_ip_id'),summary_public.get('assigned_entity_id')):
                            continue
                        pub,_=_read(gateway,node.region,'PublicIp',summary_public['id'])
                        _identity(pub,summary_public['id'],summary_public['compartment_id'])
                        if _metadata('PublicIp',pub)!=_metadata('PublicIp',summary_public):
                            raise CleanupError('Public IP association changed')
                        associations=[pub.get(field) for field in ('private_ip_id','assigned_entity_id') if pub.get(field)]
                        if not associations or any(identity!=ip['id'] for identity in associations):
                            raise CleanupError('Public IP private association IDs conflict')
                        if (pub.get('assigned_entity_type') not in (None,'PRIVATE_IP')
                                or (pub.get('assigned_entity_id') and pub.get('assigned_entity_type')!='PRIVATE_IP')):
                            raise CleanupError('Public IP assigned entity is unsupported')
                        if not isinstance(pub.get('ip_address'),str) or not pub['ip_address']:
                            raise CleanupError('Public IP address is unresolved')
                        if ip['is_primary']:
                            primary_public_ips.append(pub)
                        if pub['lifetime']=='RESERVED':
                            if pub.get('lifecycle_state')!='ASSIGNED':
                                raise CleanupError('Reserved public IP association is transitional')
                            retained_public_ips.append({field:pub.get(field) for field in
                                ('id','compartment_id','private_ip_id','assigned_entity_id','lifetime','ip_address')})
                            continue  # Preserved resource; automatic unassignment is disclosed.
                        if pub['compartment_id'] not in scope or pub.get('lifecycle_state')!='ASSIGNED':
                            raise CleanupError('Ephemeral public IP cascade is external or unresolved')
                        children.append(_node('PublicIp',pub,node.region,self))
                # The VNIC's primary address provides independent evidence that
                # complete association lists actually contain its primary IP.
                if (len(primary_private_ips)!=1 or not vnic.get('private_ip')
                        or primary_private_ips[0]['ip_address']!=vnic['private_ip']):
                    raise CleanupError('VNIC primary private IP is missing or contradicts inventory')
                if vnic.get('public_ip'):
                    if len(primary_public_ips)!=1 or primary_public_ips[0]['ip_address']!=vnic['public_ip']:
                        raise CleanupError('VNIC primary public IP is missing or contradicts inventory')
                elif primary_public_ips:
                    raise CleanupError('Public IP inventory contradicts the VNIC primary address')
            else:
                if kind=='VolumeAttachment' and row.get('attachment_type') not in ('iscsi','paravirtualized'):
                    raise CleanupError('Unsupported attachment subtype')
                field='boot_volume_id' if kind=='BootVolumeAttachment' else 'volume_id'
                if not row.get(field):
                    raise CleanupError('Missing typed attached volume identity')
                volume_kind='BootVolume' if kind=='BootVolumeAttachment' else 'Volume'
                # Boot volumes used as data have a bootvolume OCID, not volume.
                if str(row[field]).startswith('ocid1.bootvolume.'):
                    volume_kind='BootVolume'
                volume,_=_read(gateway,node.region,volume_kind,row[field])
                preserved_volume_ids.append(volume['id'])
                if volume['compartment_id'] in scope:
                    edges.append(Edge(node.key,volume['id'],'Preserved volume is independently deleted after instance'))
        if len({child.key for child in children}) != len(children):
            raise CleanupError('Duplicate instance cascade identity')
        children=[replace(child,action='cascade',metadata=dict(child.metadata,cascade_owner=node.key,cascade_verified=True)) for child in children]
        references=sorted({edge.after for edge in edges})
        owner=replace(node,metadata=dict(node.metadata,cascade_members=sorted(child.key for child in children),
                                        cascade_references=references,
                                        retained_public_ips=sorted(retained_public_ips,key=lambda ip:ip['id']),
                                        preserved_volume_ids=sorted(set(preserved_volume_ids)),
                                        cascade_snapshot={child.key:{'resource_type':child.resource_type,
                                            'compartment_id':child.compartment_id,
                                            'references':_metadata(child.resource_type,child.metadata)} for child in children}))
        return owner,children,edges

    def _dependencies(self,gateway,node,row,scope):
        kind=node.resource_type
        if kind=='Instance':
            members,_=self._producers(gateway,node.region)
            if node.key in members:
                raise CleanupError('Managed producer may recreate this instance')
            owner,_,_=self._cascade(gateway,node,scope,_attachments(gateway,node.region),self._public_ips(gateway,node.region))
            if (owner.metadata['cascade_members']!=node.metadata.get('cascade_members')
                    or owner.metadata['cascade_references']!=node.metadata.get('cascade_references')
                    or owner.metadata['cascade_snapshot']!=node.metadata.get('cascade_snapshot')
                    or owner.metadata['retained_public_ips']!=node.metadata.get('retained_public_ips')
                    or owner.metadata['preserved_volume_ids']!=node.metadata.get('preserved_volume_ids')):
                raise CleanupError('Instance cascade membership changed; refresh report')
        elif kind in ('VolumeAttachment','BootVolumeAttachment') and not node.metadata.get('cascade_owner'):
            instance=_instance_endpoint(gateway,node.region,row,scope)
            if kind=='VolumeAttachment' and row.get('attachment_type') not in ('iscsi','paravirtualized'):
                raise CleanupError('Unsupported attachment subtype')
            if kind=='BootVolumeAttachment' and instance.get('lifecycle_state')!='STOPPED':
                raise CleanupError('Boot detach requires an already stopped instance')
        elif kind in ('Vnic','PrivateIp','PublicIp','VnicAttachment','VolumeAttachment','BootVolumeAttachment'):
            # No independent delete operation is selected for network cascades.
            owner=node.metadata.get('cascade_owner')
            if not owner:
                raise CleanupError('Unverified instance cascade owner')
            instance,_=_read(gateway,node.region,'Instance',owner)
            if instance['compartment_id'] not in scope:
                raise CleanupError('Instance cascade owner moved outside scope')
            temporary=_node('Instance',instance,node.region,self)
            _,children,_=self._cascade(gateway,temporary,scope,_attachments(gateway,node.region),self._public_ips(gateway,node.region))
            if not any(child.key==node.key and child.resource_type==node.resource_type for child in children):
                raise CleanupError('Fresh typed cascade membership is unavailable')

    def corroborate_terminal_absence(self, gateway, node, scope):
        """Corroborate recorded TERMINATED/DETACHED with exact typed lists."""
        if node.resource_type not in ('Instance', 'VolumeAttachment', 'BootVolumeAttachment'):
            return False
        if node.compartment_id not in scope:
            return False
        try:
            try:
                _read(gateway, node.region, node.resource_type, node.key)
                return False
            except GatewayError as error:
                if error.status != 404:
                    return False
            if node.resource_type != 'Instance':
                rows = [row for _, row in _attachments(gateway, node.region, kinds=(node.resource_type,))]
            else:
                rows = []
                for compartment in _compartments(gateway):
                    current = gateway.items('compute', node.region, 'list_instances', {'compartment_id': compartment})
                    for row in current:
                        _identity(row, owner=compartment)
                    rows.extend(current)
            identities = [row['id'] for row in rows]
            return len(identities) == len(set(identities)) and node.key not in identities
        except Exception:
            return False

    def discover(self,gateway,compartment_id,region):
        nodes,edges,probes=[],[],[]
        scope=_scope(gateway)
        try:
            members,unsupported=self._producers(gateway,region)
            probes.append(Probe('compute:producers',region,compartment_id,'complete',
                'Full visible-tenancy instance pools and OKE node pools; arbitrary external automation is not inventoried'))
            for kind,row in unsupported:
                if row['compartment_id'] in scope:
                    nodes.append(Node(row['id'],kind,region,row['compartment_id'],row.get('display_name') or row.get('name') or '',
                        row.get('lifecycle_state') or '', '', 'unresolved',{},('Unsupported managed producer',)))
        except Exception:
            members=None
            probes.append(Probe('compute:producers',region,compartment_id,'failed','Managed producer inventory failed'))
        try:
            attachments=_attachments(gateway,region)
            probes.append(Probe('compute:attachments',region,compartment_id,'complete','Full visible-tenancy attachment inventory'))
        except Exception:
            attachments=None
            probes.append(Probe('compute:attachments',region,compartment_id,'failed','Attachment inventory failed'))
        try:
            public_ips=self._public_ips(gateway,region)
            probes.append(Probe('compute:public_ips',region,compartment_id,'complete','Reserved and ephemeral public IP association inventory'))
        except Exception:
            public_ips=None
            probes.append(Probe('compute:public_ips',region,compartment_id,'failed','Public IP cascade inventory failed'))
        try:
            rows=gateway.items('compute',region,'list_instances',{'compartment_id':compartment_id})
            for summary in rows:
                n=_node('Instance',_identity(summary,owner=compartment_id),region,self)
                try:
                    row,_=_read(gateway,region,'Instance',n.key)
                    _identity(row,n.key,compartment_id)
                    if _metadata('Instance',row)!=n.metadata:
                        raise CleanupError('Instance changed during discovery')
                    if members is None or attachments is None or public_ips is None:
                        raise CleanupError('Instance dependencies are unresolved')
                    if n.key in members:
                        if any(row['id']==members[n.key] and row['compartment_id'] in scope for _,row in unsupported):
                            edges.append(Edge(members[n.key],n.key,'Typed managed producer recreates instance'))
                        raise CleanupError('Managed producer prevents standalone termination')
                    n,children,references=self._cascade(gateway,n,scope,attachments,public_ips)
                    nodes.extend(children)
                    edges.extend(references)
                except Exception:
                    n=_blocked(n,'Managed producer, external VNIC, or unresolved full cascade dependency')
                nodes.append(n)
            probes.append(Probe('compute:instances',region,compartment_id,'complete',''))
        except Exception:
            probes.append(Probe('compute:instances',region,compartment_id,'failed','Instance inventory failed'))
        # Preserve distinct attachment nodes even when their owner cannot be deleted.
        existing={node.key for node in nodes}
        for kind,row in attachments or []:
            if row['compartment_id']==compartment_id and row['id'] not in existing:
                n=_node(kind,row,region,self)
                try:
                    live,_=_read(gateway,region,kind,n.key)
                    _identity(live,n.key,compartment_id)
                    if _metadata(kind,live)!=n.metadata:
                        raise CleanupError('Attachment dependency changed')
                    self._dependencies(gateway,n,live,scope)
                except Exception:
                    n=_blocked(n,'Attachment endpoint, subtype, or detach eligibility is unresolved')
                nodes.append(n)
                if kind in ('VolumeAttachment','BootVolumeAttachment'):
                    field='boot_volume_id' if kind=='BootVolumeAttachment' else 'volume_id'
                    volume_kind='BootVolume' if kind=='BootVolumeAttachment' or str(row.get(field)).startswith('ocid1.bootvolume.') else 'Volume'
                    try:
                        volume,_=_read(gateway,region,volume_kind,row[field])
                        if volume['compartment_id'] in scope:
                            edges.append(Edge(n.key,volume['id'],'Typed attachment must detach before volume deletion'))
                    except Exception:
                        nodes[-1]=_blocked(nodes[-1],'Attached volume identity is unreadable')
        return nodes,edges,probes
