"""Investigate an actual service rejection using exact IDs and typed relations.

No finding authorizes deletion. Search corroborates exact reported identities;
registered GETs establish their current ownership. Unknown relations remain an
explicit manual action, and external resources are never deletion candidates.
"""
from dataclasses import dataclass
import re
import oci

from .gateway import GatewayError
from .model import Node
from .actions import _contract
from .handlers.core import _identity
from .handlers.network import NETWORK_OPERATIONS


@dataclass(frozen=True)
class DependencyFinding:
    target_id: str
    resource: Node | None
    evidence: str
    external: bool
    guidance: str


# These codes describe failed operations, not generic HTTP conflict status.
_DEPENDENCY_CODES=frozenset({'ResourceLocked'})
_VERIFIED_WRITES=frozenset((service,operation) for service,operation in (
    ('identity','delete_policy'),('identity','delete_compartment'),
    ('compute','terminate_instance'),('compute','detach_volume'),('compute','detach_boot_volume'),
    ('blockstorage','delete_volume'),('blockstorage','delete_boot_volume'),
    ('blockstorage','delete_volume_backup'),('blockstorage','delete_boot_volume_backup'),
    ('load_balancer','delete_load_balancer'),('network_load_balancer','delete_network_load_balancer'),
    ('log_analytics','delete_log_analytics_entity'),('log_analytics','delete_log_analytics_object_collection_rule'),
    ('log_analytics','delete_log_analytics_em_bridge'),('service_connector','delete_service_connector'),
    ('kms_vault','schedule_vault_deletion'),('kms_management','schedule_key_deletion'),
    ('vault','schedule_secret_deletion'),('certificates','schedule_certificate_deletion'),
    ('certificates','schedule_certificate_authority_deletion'),('certificates','delete_ca_bundle'),
)) | frozenset(('network',v[2]) for v in NETWORK_OPERATIONS.values())
_NETWORK_DELETES=frozenset(v[2] for v in NETWORK_OPERATIONS.values())


def is_dependency_rejection(error):
    if not isinstance(error,GatewayError):return False
    if error.service=='identity' and error.operation=='bulk_delete_resources' and getattr(error,'verified_member_failure',False) is True:
        return (error.status in (None,400,409) and error.service=='identity' and error.operation=='bulk_delete_resources'
                and getattr(error,'verified_member_failure',False) is True
                and error.code=='ResourceLocked'
                and bool(re.search(r'(?i)(dependenc|is in use|has resources|is associated with)',error.message)))
    if error.status not in (400,409):return False
    if error.service=='object_storage' and error.operation=='delete_bucket' and error.status==409 and error.code=='BucketNotEmpty':return True
    if (error.service,error.operation) not in _VERIFIED_WRITES:return False
    if error.status==409 and error.code in _DEPENDENCY_CODES:return True
    # OCI Conflict is accepted only with explicit dependency wording from a
    # registered DELETE/schedule operation; arbitrary 409 remains uncertain.
    # OCI error semantics: https://docs.oracle.com/en-us/iaas/Content/API/References/apierrors.htm
    return (error.status==409 and error.code=='Conflict' and bool(re.search(r'(?i)(has dependencies|is in use|has resources|is associated with)',error.message)))


def is_confirmed_rejection(error):
    return (is_dependency_rejection(error) or isinstance(error,GatewayError)
            and error.status==412 and error.code=='NoEtagMatch')


def _raise_authorization(error):
    if isinstance(error,GatewayError) and error.status in (401,403):raise error


def _manual(node,reason):
    return DependencyFinding(node.key,None,reason,False,
        'Inspect this resource and its dependent resources in the OCI service console; remove or detach the dependency, then refresh and retry. No additional deletion target was verified.')


def _external_owner(gateway,plan,owner):
    # New compartments may be absent from the saved inventory. Authenticate their
    # current ancestry with exact GETs before offering an expanded target set.
    seen=set()
    for _ in range(128):
        if not isinstance(owner,str) or owner in seen or owner==plan.tenancy_id:return True
        seen.add(owner)
        row,_=gateway.read('identity',plan.home_region,'get_compartment',{'compartment_id':owner})
        _identity(row,owner)
        if row.get('lifecycle_state')!='ACTIVE':return True
        if owner==plan.parent_id:return False
        owner=row['compartment_id']
    return True


def _typed_finding(gateway,plan,target,kind,key,summary=None,metadata=None,evidence='Typed resource association'):
    service,get,_,parameter=_contract(kind)
    params={parameter:key}; endpoint=None; metadata=dict(metadata or {})
    if service=='log_analytics':
        namespace=metadata.get('namespace') or target.metadata.get('namespace')
        if not isinstance(namespace,str) or not namespace:return _manual(target,'Dependency namespace is unavailable')
        params['namespace_name']=namespace;metadata['namespace']=namespace
    if service=='kms_management':return _manual(target,'Key dependency needs fresh vault endpoint verification')
    row,_=gateway.read(service,target.region,get,params);_identity(row,key)
    if summary is not None and row['compartment_id']!=summary.get('compartment_id'):
        return _manual(target,'Dependency ownership changed between Search and typed read')
    metadata.update({k:v for k,v in row.items() if k in ('vcn_id','vault_id','namespace') and isinstance(v,str)})
    resource=Node(key,kind,target.region,row['compartment_id'],row.get('display_name') or row.get('name') or '',row.get('lifecycle_state') or '','', 'unresolved',metadata)
    # Registry only assigns a code-defined report policy. Actions recheck live
    # ownership and lifecycle after the user confirms adding this target.
    if row['compartment_id'] in plan.compartments:
        external=False
    else:
        try:external=_external_owner(gateway,plan,row['compartment_id'])
        except Exception as error:
            _raise_authorization(error);external=True
    guidance='External resource: detach or change its association manually; it will not be deleted.' if external else 'Confirm this dependency explicitly before any deletion.'
    return DependencyFinding(target.key,resource,evidence,external,guidance)


def _search_id(gateway,plan,node,key,registry):
    query="query all resources where identifier = '"+key+"'"
    details=oci.resource_search.models.StructuredSearchDetails(query=query)
    rows=gateway.items('search',node.region,'search_resources',{'search_details':details})
    matches=[r for r in rows if r.get('identifier')==key]
    if len(matches)!=1:return _manual(node,'Exact dependency Search identity is missing or conflicting: '+key)
    row=matches[0]
    from .inventory import canonical_type
    kind=canonical_type(row.get('resource_type',''))
    try:
        finding=_typed_finding(gateway,plan,node,kind,key,{'compartment_id':row.get('compartment_id')},evidence='Service rejection OCID corroborated by exact Search and typed GET')
        if finding.resource is not None and registry is not None:
            from dataclasses import replace
            finding=replace(finding,resource=registry.classify(finding.resource))
        return finding
    except Exception as error:
        _raise_authorization(error)
        return _manual(node,'Exact dependency type or ownership could not be verified: '+key)


def _targeted_associations(gateway,plan,node):
    results=[]; kind=node.resource_type
    if kind=='Bucket':
        from .actions import _target
        from .handlers.storage import Storage
        from .candidates import CandidateSnapshot
        from dataclasses import replace
        row,_,_,_,_,_=_target(gateway,plan,node)
        candidate=replace(node,display_name=row['name'])
        from .actions import _ReadAuthorizationTracker
        tracked=_ReadAuthorizationTracker(gateway)
        snapshot=CandidateSnapshot(tracked,[candidate])
        handler=Storage()
        nodes,edges,probes=handler.discover(snapshot,node.compartment_id,node.region)
        if tracked.error is not None:raise tracked.error
        if any(p.status!='complete' for p in probes):return [_manual(node,'Exact bucket child inventory failed; no partial targets are actionable')]
        parent=next((n for n in nodes if n.key==node.key and n.resource_type=='Bucket'),None)
        if parent is None:return [_manual(node,'Rejected bucket identity was not corroborated by its complete child inventory')]
        results.append(DependencyFinding(node.key,parent,'Refreshed exact bucket-owned inventory baseline',False,'Save this bucket baseline before confirming or deleting its children.'))
        for child in nodes:
            if child.key==node.key:continue
            results.append(DependencyFinding(node.key,child,'Exact bucket-owned child inventory',False,
                'Confirm this exact bucket-owned child before deletion; retention and replication protections remain enforced.'))
        return results
    # Fixed parameter mappings, constrained by the rejected owner identity.
    if kind in ('Vcn','Subnet'):
        calls=(('Subnet','list_subnets','vcn_id'),('InternetGateway','list_internet_gateways','vcn_id'),('NatGateway','list_nat_gateways','vcn_id'),('ServiceGateway','list_service_gateways','vcn_id'),('LocalPeeringGateway','list_local_peering_gateways','vcn_id'),('NetworkSecurityGroup','list_network_security_groups','vcn_id')) if kind=='Vcn' else ()
        for child,operation,field in calls:
            for row in gateway.items('network',node.region,operation,{'compartment_id':node.compartment_id,field:node.key}):
                if row.get(field)!=node.key:continue
                if row.get('lifecycle_state') in ('DELETED','TERMINATED'):continue
                results.append(_typed_finding(gateway,plan,node,child,row['id'],row,evidence='Targeted network '+field+' association'))
        if kind=='Subnet':
            for row in gateway.items('network',node.region,'list_private_ips',{'subnet_id':node.key}):
                if row.get('subnet_id')==node.key:
                    # Private IP deletion isn't enabled; its owning instance/VNIC
                    # must be investigated explicitly rather than guessed.
                    results.append(_manual(node,'Subnet is associated with private IP '+str(row.get('id'))+'; detach its verified instance/VNIC owner manually'))
    if kind=='NetworkSecurityGroup':
        for row in gateway.items('network',node.region,'list_network_security_group_vnics',{'network_security_group_id':node.key}):
            results.append(_manual(node,'Network security group membership references VNIC '+str(row.get('vnic_id'))+'; remove this membership manually'))
    if kind=='LogAnalyticsEntity':
        ns=node.metadata.get('namespace')
        if not isinstance(ns,str) or not ns:return []
        for row in gateway.items('log_analytics',node.region,'list_entity_associations',{'namespace_name':ns,'log_analytics_entity_id':node.key,'direct_or_all_associations':'ALL'}):
            key=row.get('entity_id') or row.get('association_entity_id')
            if isinstance(key,str) and key!=node.key:
                results.append(_typed_finding(gateway,plan,node,'LogAnalyticsEntity',key,metadata={'namespace':ns},evidence='Targeted entity association'))
            else:results.append(_manual(node,'Entity association requires manual removal; no supported independent association-delete contract'))
    if kind in ('Certificate','CertificateAuthority','CaBundle'):
        for row in gateway.items('certificates',node.region,'list_associations',{'certificates_resource_id':node.key}):
            results.append(_manual(node,'Certificate association references '+str(row.get('associated_resource_id') or row.get('resource_id'))+'; remove its consumer association manually'))
    return results


def investigate_rejection(gateway,plan,node,error,registry):
    if not is_dependency_rejection(error):
        return [_manual(node,'Service response does not establish a dependency rejection')]
    # This alphabet cannot inject a Structured Search quoted value. Truncate the
    # message at the gateway boundary and limit targets to prevent response abuse.
    if node.resource_type=='Bucket':
        try:return _targeted_associations(gateway,plan,node) or [_manual(node,'Bucket rejection has no corroborated child identity')]
        except Exception as error:
            _raise_authorization(error)
            return [_manual(node,'Exact rejected bucket child inventory could not be verified')]
    ids=list(dict.fromkeys(re.findall(r'ocid1\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_.-]+',error.message)))[:16]
    results=[_search_id(gateway,plan,node,key,registry) for key in ids if key!=node.key]
    if not results:
        try:results=_targeted_associations(gateway,plan,node)
        except Exception as error:
            _raise_authorization(error)
            results=[_manual(node,'Targeted dependency association could not be read or corroborated')]
    return results or [_manual(node,'This service rejection has no verified dependency identifier or supported targeted investigator')]
