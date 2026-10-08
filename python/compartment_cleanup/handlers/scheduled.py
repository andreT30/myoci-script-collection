"""Scheduled OCI deletion with positive terminal evidence and fresh cascade proof.

OCI does not guarantee a readable DELETED record after purge. A missing read
therefore remains unresolved, even after a confirmed deletion deadline. KMS key
membership scans are not an atomic snapshot; conditional owner writes cannot lock
other resources against concurrent creation or compartment movement.
"""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import oci

from .base import Handler
from .core import _identity, _blocked, _scope, _compartments
from ..model import CleanupError, Node, Edge, Observation, Probe, Submission, child_key

_CONTRACTS = {
    'Certificate': ('certificates','list_certificates','get_certificate','schedule_certificate_deletion','certificate_id','schedule_certificate_deletion_details',oci.certificates_management.models.ScheduleCertificateDeletionDetails),
    'CertificateAuthority': ('certificates','list_certificate_authorities','get_certificate_authority','schedule_certificate_authority_deletion','certificate_authority_id','schedule_certificate_authority_deletion_details',oci.certificates_management.models.ScheduleCertificateAuthorityDeletionDetails),
    'CaBundle': ('certificates','list_ca_bundles','get_ca_bundle','delete_ca_bundle','ca_bundle_id',None,None),
    'Vault': ('kms_vault','list_vaults','get_vault','schedule_vault_deletion','vault_id','schedule_vault_deletion_details',oci.key_management.models.ScheduleVaultDeletionDetails),
    'Key': ('kms_management','list_keys','get_key','schedule_key_deletion','key_id','schedule_key_deletion_details',oci.key_management.models.ScheduleKeyDeletionDetails),
    'Secret': ('vault','list_secrets','get_secret','schedule_secret_deletion','secret_id','schedule_secret_deletion_details',oci.vault.models.ScheduleSecretDeletionDetails),
}
_FIELDS = {
    'Certificate': ('issuer_certificate_authority_id','certificate_revocation_list_details'),
    'CertificateAuthority': ('issuer_certificate_authority_id','kms_key_id','certificate_revocation_list_details','config_type'),
    'CaBundle': (),
    'Vault': ('vault_type','is_primary','replica_details'),
    'Key': ('vault_id','protection_mode','is_primary','replica_details'),
    'Secret': ('vault_id','key_id','is_replica'),
}
_PENDING = ('PENDING_DELETION','SCHEDULING_DELETION','DELETING')
_ELIGIBLE = {'Certificate':('ACTIVE',),'CertificateAuthority':('ACTIVE',),'CaBundle':('ACTIVE',),
             'Vault':('ACTIVE',),'Key':('ENABLED','DISABLED'),'Secret':('ACTIVE',)}
_CASCADE = ('cascade_owner','cascade_members','cascade_verified')


def _utc(value):
    if value is None: return None
    try:
        parsed = value if isinstance(value,datetime) else datetime.fromisoformat(value.replace('Z','+00:00'))
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0): raise ValueError()
        return value if isinstance(value,str) else parsed.isoformat().replace('+00:00','Z')
    except (AttributeError,TypeError,ValueError):
        raise CleanupError('Service schedule is not an aware UTC timestamp') from None


def scheduled_time(kind: str, now: datetime) -> datetime:
    if kind not in _CONTRACTS or kind=='CaBundle' or not isinstance(now,datetime) or now.tzinfo is None or now.utcoffset()!=timedelta(0):
        raise CleanupError('Schedule requires a supported kind and aware UTC time')
    return now + timedelta(days=1 if kind in ('Certificate','Secret') else 7,minutes=5)


def validate_cascade(nodes: list[Node], scope: set[str]) -> tuple[str, ...]:
    if any(n.compartment_id not in scope or n.blockers or n.action=='unresolved' for n in nodes):
        raise CleanupError('Cascade contains an external or unresolved identity')
    keys=[n.key for n in nodes]
    if len(keys)!=len(set(keys)): raise CleanupError('Duplicate cascade identity')
    return tuple(sorted(keys))


def _metadata(kind,row):
    result={k:row[k] for k in _FIELDS[kind] if row.get(k) is not None and k not in ('replica_details','certificate_revocation_list_details')}
    # Preserve only the presence of unproven destructive replication/CRL effects.
    if row.get('replica_details') is not None: result['has_replica_details']=True
    if row.get('certificate_revocation_list_details') is not None: result['has_crl_details']=True
    when=_utc(row.get('time_of_deletion'))
    if when: result['scheduled_at']=when
    return result


def _node(kind,row,region,handler):
    _identity(row)
    return Node(row['id'],kind,region,row['compartment_id'],row.get('display_name') or '',
                row.get('lifecycle_state') or '',handler.name,'delete' if kind=='CaBundle' else 'schedule',_metadata(kind,row))


class ScheduledResources(Handler):
    name='scheduled'
    resource_types=tuple(_CONTRACTS)+('SecretReplica',)
    action='schedule'
    metadata_keys=tuple(sorted({k for fields in _FIELDS.values() for k in fields}
        |set(_CASCADE)|{'scheduled_at','has_replica_details','has_crl_details','replication_targets','regional_replicas','source_secret_id','source_region','key_consumers'}))
    retained_reference_fields=('kms_key_id','vault_id','key_id','issuer_certificate_authority_id')

    def classify(self,node):
        if node.resource_type=='SecretReplica':
            return replace(node,handler=self.name,action='unresolved',metadata={k:v for k,v in node.metadata.items() if k in ('source_secret_id','source_region','scheduled_at')})
        allowed=set(_FIELDS[node.resource_type])-{'replica_details','certificate_revocation_list_details'}
        allowed.update(('scheduled_at','has_replica_details','has_crl_details'))
        if node.resource_type=='Secret': allowed.update(('replication_targets','regional_replicas'))
        if node.resource_type in ('Key','Vault'): allowed.update(_CASCADE); allowed.add('key_consumers')
        metadata={k:v for k,v in node.metadata.items() if k in allowed}
        # Nested regional evidence is identifying data only, never arbitrary SDK
        # fields, tags or content from a saved artifact. Execution renews it live.
        for field,keys in (('key_consumers',('id','kind','region','compartment_id','key_id','namespace','bucket_name','reference','target_region','target_vault_id','target_key_id','source_vault_id','source_key_id','replica_compartment_id','target_vault_compartment_id','target_key_compartment_id')),
                           ('replication_targets',('target_region','target_vault_id','target_key_id')),
                           ('regional_replicas',('id','region','compartment_id','lifecycle_state','source_region','source_vault_id','source_key_id','target_region','target_vault_id','target_key_id','scheduled_at'))):
            if field in metadata:
                rows=metadata[field]
                metadata[field]=[{k:r[k] for k in keys if isinstance(r.get(k),str)} for r in rows if type(r) is dict] if type(rows) is list else []
        return replace(node,handler=self.name,action='delete' if node.resource_type=='CaBundle' else 'cascade' if node.resource_type=='Key' and metadata.get('cascade_owner') else 'schedule',metadata=metadata)

    def _vault(self,gateway,region,key):
        row,headers=gateway.read('kms_vault',region,'get_vault',{'vault_id':key})
        _identity(row,key)
        if row.get('lifecycle_state')!='DELETED' and not isinstance(row.get('management_endpoint'),str):
            raise CleanupError('Vault endpoint unavailable')
        return row,headers

    def _read(self,gateway,node):
        service,_,operation,_,parameter,_,_=_CONTRACTS[node.resource_type]
        endpoint=None
        if node.resource_type=='Key':
            vault_id=node.metadata.get('vault_id')
            if not isinstance(vault_id,str) or not vault_id: raise CleanupError('Key vault identity is unavailable')
            vault,_=self._vault(gateway,node.region,vault_id)
            endpoint=vault.get('management_endpoint')
            if not endpoint: raise CleanupError('Key endpoint cannot be renewed')
        row,headers=gateway.read(service,node.region,operation,{parameter:node.key},endpoint=endpoint)
        _identity(row,node.key)
        if node.resource_type=='Key' and row.get('vault_id')!=node.metadata.get('vault_id'):
            raise CleanupError('Key vault identity changed')
        return row,headers,endpoint

    def _unreplicated(self,gateway,region,vault,key=None):
        if vault.get('replica_details') is not None or vault.get('is_primary') is not True or vault.get('vault_type') not in ('DEFAULT','VIRTUAL_PRIVATE','EXTERNAL'):
            raise CleanupError('Vault replication identity is unproven')
        replicas=gateway.items('kms_vault',region,'list_vault_replicas',{'vault_id':vault['id']})
        if any(r.get('status')!='DELETED' for r in replicas):
            raise CleanupError('Vault replica scope is unproven')
        if key is not None and (key.get('replica_details') is not None or key.get('is_primary') is not True or key.get('protection_mode') not in ('HSM','SOFTWARE','EXTERNAL')):
            raise CleanupError('Key replication identity is unproven')

    def _key_set(self,gateway,region,vault,scope,previous=(),allow_references=False):
        self._unreplicated(gateway,region,vault)
        if vault.get('vault_type')=='EXTERNAL': raise CleanupError('External vault cascade count unavailable')
        endpoint=vault['management_endpoint']; keys={}; counts={'HSM':0,'SOFTWARE':0}
        for compartment in _compartments(gateway):
            for summary in gateway.items('kms_management',region,'list_keys',{'compartment_id':compartment},endpoint=endpoint):
                _identity(summary,owner=compartment)
                row,_=gateway.read('kms_management',region,'get_key',{'key_id':summary['id']},endpoint=endpoint)
                _identity(row,summary['id'],compartment)
                if row.get('vault_id')!=vault['id']: raise CleanupError('Endpoint key membership mismatch')
                if row['id'] in keys: raise CleanupError('Duplicate key membership')
                if row.get('lifecycle_state')=='DELETED': continue
                self._unreplicated(gateway,region,vault,row)
                mode=row.get('protection_mode')
                if mode not in counts: raise CleanupError('Unsupported key protection mode')
                if row['compartment_id'] not in scope: raise CleanupError('External key blocks vault cascade')
                if row.get('lifecycle_state') not in _ELIGIBLE['Key']+_PENDING: raise CleanupError('Key lifecycle unresolved')
                _utc(row.get('time_of_deletion'))
                keys[row['id']]=row; counts[mode]+=1
        usage,_=gateway.read('kms_vault',region,'get_vault_usage',{'vault_id':vault['id']})
        for field,mode in (('key_count','HSM'),('software_key_count','SOFTWARE')):
            count=usage.get(field)
            if type(count) is not int or count<0 or count!=counts[mode]: raise CleanupError('Vault usage count does not prove complete key identity set')
        consumers=self._key_consumers(gateway,set(keys),scope,previous,record_external=allow_references)
        if consumers and not allow_references: raise CleanupError('Live vault key consumers remain')
        for key in keys.values(): key['__key_consumers']=[c for c in consumers if c['key_id']==key['id']]
        return keys

    def _outside_consumers(self,consumers,scope):
        return any(c.get(field) is not None and c[field] not in scope for c in consumers
                   for field in ('compartment_id','replica_compartment_id','target_vault_compartment_id','target_key_compartment_id'))

    def _consumer_read(self,gateway,ref):
        kind=ref['kind']; region=ref['region']
        mapping={'Volume':('blockstorage','get_volume','volume_id'),
                 'BootVolume':('blockstorage','get_boot_volume','boot_volume_id'),
                 'VolumeBackup':('blockstorage','get_volume_backup','volume_backup_id'),
                 'BootVolumeBackup':('blockstorage','get_boot_volume_backup','boot_volume_backup_id'),
                 'CertificateAuthority':('certificates','get_certificate_authority','certificate_authority_id'),
                 'Secret':('vault','get_secret','secret_id')}
        if kind=='Bucket':
            params={'namespace_name':ref['namespace'],'bucket_name':ref['bucket_name']}
            row,_=gateway.read('object_storage',region,'get_bucket',params)
            _identity(row,ref.get('id'))
            if row.get('namespace')!=ref['namespace'] or row.get('name')!=ref['bucket_name']: raise CleanupError('Bucket reverse identity mismatch')
        else:
            service,operation,parameter=mapping[kind]
            row,_=gateway.read(service,region,operation,{parameter:ref['id']}); _identity(row,ref['id'])
        return row

    def _consumer_keys(self,kind,row):
        field='key_id' if kind=='Secret' else 'kms_key_id'
        result=[]
        key=row.get(field)
        if key is not None:
            if not isinstance(key,str) or not key: raise CleanupError('Malformed typed key reference')
            result.append((key,field))
        return result

    def _target_key_consumers(self,gateway,ref,source,key_ids,scope,previous,record_external=False):
        if source.get('is_replica') is not False: raise CleanupError('Secret source role unresolved')
        targets=self._targets(source)
        for old in previous:
            if old.get('kind')=='Secret' and old.get('region')==ref['region'] and old.get('id')==ref['id'] and old.get('reference')=='replication_target':
                target={k:old.get(k) for k in ('target_region','target_vault_id','target_key_id')}
                if any(not isinstance(v,str) or not v for v in target.values()): raise CleanupError('Historical target key evidence malformed')
                if target not in targets: targets.append(target)
        consumers=[]
        for target in targets:
            if target['target_key_id'] not in key_ids: continue
            region=target['target_region']
            if region not in gateway.regions or region==ref['region']: raise CleanupError('Target key region unresolved')
            replica,_=gateway.read('vault',region,'get_secret',{'secret_id':ref['id']}); _identity(replica,ref['id'])
            expected={'source_region':ref['region'],'source_vault_id':source.get('vault_id'),'source_key_id':source.get('key_id')}
            if any(not isinstance(v,str) or not v for v in expected.values()): raise CleanupError('Secret source linkage malformed')
            info=replica.get('source_region_information')
            if replica.get('is_replica') is not True or type(info) is not dict or any(info.get(k)!=v for k,v in expected.items()):
                raise CleanupError('Replica target key linkage unresolved')
            # A source DELETED observation does not establish asynchronous regional
            # deletion. Only the exact regional replica's positive state releases it.
            if replica.get('lifecycle_state')=='DELETED': continue
            if replica.get('lifecycle_state') not in _ELIGIBLE['Secret']+_PENDING: raise CleanupError('Target replica lifecycle unresolved')
            if not record_external and (source['compartment_id'] not in scope or replica['compartment_id'] not in scope): raise CleanupError('External regional secret key consumer')
            vault,_=self._vault(gateway,region,target['target_vault_id'])
            key,_=gateway.read('kms_management',region,'get_key',{'key_id':target['target_key_id']},endpoint=vault['management_endpoint']); _identity(key,target['target_key_id'])
            if key.get('vault_id')!=vault['id'] or (not record_external and (key['compartment_id'] not in scope or vault['compartment_id'] not in scope)): raise CleanupError('Replica target encryption scope unresolved')
            consumers.append(dict(ref,compartment_id=source['compartment_id'],key_id=target['target_key_id'],reference='replication_target',
                                  source_vault_id=source['vault_id'],source_key_id=source['key_id'],replica_compartment_id=replica['compartment_id'],
                                  target_vault_compartment_id=vault['compartment_id'],target_key_compartment_id=key['compartment_id'],**target))
        return targets,consumers

    def _key_consumers(self,gateway,key_ids,scope,previous=(),record_external=False):
        """Supported reverse consumers only; OCI exposes no universal key index.

        Scan every readable tenancy compartment and subscribed region. Failed
        required pages fail closed. Known old consumers also require direct reads;
        their absence from a new list cannot prove that they have been removed.
        """
        inventories=(('Volume','blockstorage','list_volumes'),('BootVolume','blockstorage','list_boot_volumes'),
                     ('VolumeBackup','blockstorage','list_volume_backups'),('BootVolumeBackup','blockstorage','list_boot_volume_backups'),
                     ('CertificateAuthority','certificates','list_certificate_authorities'),('Secret','vault','list_secrets'),
                     ('Bucket','object_storage','list_buckets'))
        known={}
        for region in gateway.regions:
            namespace,_=gateway.read('object_storage',region,'get_namespace',{})
            if not isinstance(namespace,str) or not namespace: raise CleanupError('Object storage namespace unknown')
            for owner in _compartments(gateway):
                for kind,service,operation in inventories:
                    params={'compartment_id':owner}
                    if kind=='Bucket': params['namespace_name']=namespace
                    for summary in gateway.items(service,region,operation,params):
                        ref={'kind':kind,'region':region,'compartment_id':owner}
                        if kind=='Bucket':
                            # BucketSummary has no OCID. The GET supplies exact
                            # identity, independently of the canonical name path.
                            if (summary.get('compartment_id')!=owner or summary.get('namespace')!=namespace
                                    or not isinstance(summary.get('name'),str) or not summary['name']):
                                raise CleanupError('Bucket summary lacks canonical identity')
                            ref.update(namespace=namespace,bucket_name=summary['name'])
                        else:
                            _identity(summary,owner=owner); ref['id']=summary['id']
                        row=self._consumer_read(gateway,ref); _identity(row,ref.get('id'),owner)
                        ref['id']=row['id']
                        known[(kind,region,ref['id'])]=(ref,row)
        for ref in previous:
            if type(ref) is not dict or ref.get('key_id') not in key_ids: raise CleanupError('Historical consumer proof malformed')
            identity=(ref.get('kind'),ref.get('region'),ref.get('id'))
            if identity not in known:
                row=self._consumer_read(gateway,ref)
                known[identity]=(ref,row)
        consumers=[]
        for ref,row in known.values():
            terminal='TERMINATED' if ref['kind'] in ('Volume','BootVolume','VolumeBackup','BootVolumeBackup') else 'DELETED'
            if ref['kind']=='Secret':
                if row.get('is_replica') is False:
                    _,regional=self._target_key_consumers(gateway,ref,row,key_ids,scope,previous,record_external)
                elif row.get('is_replica') is True and row.get('lifecycle_state')!='DELETED':
                    info=row.get('source_region_information')
                    if type(info) is not dict or info.get('source_region') not in gateway.regions: raise CleanupError('Regional secret source identity unresolved')
                    source_ref=dict(ref,region=info['source_region'])
                    source=self._consumer_read(gateway,source_ref)
                    targets,regional=self._target_key_consumers(gateway,source_ref,source,key_ids,scope,previous,record_external)
                    if not any(t['target_region']==ref['region'] for t in targets): raise CleanupError('Live replica encryption target identity is unavailable')
                elif row.get('is_replica') is True: regional=[]
                else: raise CleanupError('Secret reverse consumer role unresolved')
                for evidence in regional:
                    if evidence not in consumers: consumers.append(evidence)
            if row.get('lifecycle_state')==terminal: continue
            for key,field in self._consumer_keys(ref['kind'],row):
                if key not in key_ids: continue
                if not record_external and row['compartment_id'] not in scope: raise CleanupError('External typed key consumer blocks deletion')
                evidence=dict(ref,compartment_id=row['compartment_id'],key_id=key,reference=field)
                if evidence not in consumers: consumers.append(evidence)
        return sorted(consumers,key=lambda x:(x['key_id'],x['region'],x['kind'],x['id'],x['reference']))

    def _consumers(self,gateway,node,scope):
        consumers=[]
        for row in gateway.items('certificates',node.region,'list_associations',{'certificates_resource_id':node.key}):
            if (not isinstance(row.get('id'),str) or not row['id'] or row.get('certificates_resource_id')!=node.key
                    or row.get('association_type')!={'Certificate':'CERTIFICATE','CertificateAuthority':'CERTIFICATE_AUTHORITY','CaBundle':'CA_BUNDLE'}[node.resource_type]
                    or row.get('lifecycle_state') not in ('CREATING','ACTIVE','UPDATING','DELETING','FAILED')
                    or not isinstance(row.get('associated_resource_id'),str)):
                raise CleanupError('Malformed certificate association')
            key=row['associated_resource_id']
            mapping={'loadbalancer':('load_balancer','get_load_balancer','load_balancer_id'),
                     'networkloadbalancer':('network_load_balancer','get_network_load_balancer','network_load_balancer_id')}
            parts=key.split('.')
            if len(parts)<3 or parts[0]!='ocid1' or parts[1] not in mapping: raise CleanupError('Unsupported certificate consumer')
            service,operation,parameter=mapping[parts[1]]
            consumer,_=gateway.read(service,node.region,operation,{parameter:key}); _identity(consumer,key)
            if consumer['compartment_id'] not in scope: raise CleanupError('External certificate consumer')
            references=[]
            for field in ('listeners','backend_sets'):
                values=consumer.get(field) or {}
                if type(values) is not dict: raise CleanupError('TLS consumer configuration malformed')
                for value in values.values():
                    if type(value) is not dict: raise CleanupError('TLS consumer configuration malformed')
                    ssl=value.get('ssl_configuration') or {}
                    if type(ssl) is not dict: raise CleanupError('TLS consumer configuration malformed')
                    for ref in ('certificate_ids','trusted_certificate_authority_ids'):
                        ids=ssl.get(ref) or []
                        if type(ids) is not list or any(not isinstance(x,str) for x in ids): raise CleanupError('TLS references malformed')
                        references.extend(ids)
            if node.key not in references: raise CleanupError('Association lacks typed consumer corroboration')
            consumers.append(key)
        return consumers

    def _issued(self,gateway,node,scope):
        children=[]
        for kind in ('Certificate','CertificateAuthority'):
            service,listing,operation,_,parameter,_,_=_CONTRACTS[kind]
            for summary in gateway.items(service,node.region,listing,{'issuer_certificate_authority_id':node.key}):
                _identity(summary)
                row,_=gateway.read(service,node.region,operation,{parameter:summary['id']}); _identity(row,summary['id'])
                if row.get('issuer_certificate_authority_id')!=node.key: raise CleanupError('Issuer relationship mismatch')
                if row['compartment_id'] not in scope: raise CleanupError('External issued child')
                if row.get('lifecycle_state')!='DELETED': children.append(row['id'])
        return children

    def _targets(self,row):
        config=row.get('replication_config')
        if config is None: return []
        if type(config) is not dict or type(config.get('replication_targets')) is not list: raise CleanupError('Secret replication configuration malformed')
        result=[]
        for target in config['replication_targets']:
            if type(target) is not dict or any(not isinstance(target.get(k),str) or not target[k] for k in ('target_region','target_vault_id','target_key_id')):
                raise CleanupError('Secret replication target identity malformed')
            result.append({k:target[k] for k in ('target_region','target_vault_id','target_key_id')})
        regions=[x['target_region'] for x in result]
        if len(set(regions))!=len(regions): raise CleanupError('Duplicate secret replication region')
        return sorted(result,key=lambda x:x['target_region'])

    def _secret_group(self,gateway,node,row,scope,terminal=False):
        if row.get('is_replica') is not False: raise CleanupError('Only a proven source secret can be scheduled')
        for field in ('vault_id','key_id'):
            if not isinstance(row.get(field),str) or not row[field]: raise CleanupError('Source secret dependency unavailable')
        targets=self._targets(row)
        previous=node.metadata.get('replication_targets')
        if previous is not None and previous!=targets:
            if terminal and not targets: targets=previous
            else: raise CleanupError('Secret replica set changed; refresh report')
        if not terminal:
            vault,_=self._vault(gateway,node.region,row['vault_id'])
            key,_=gateway.read('kms_management',node.region,'get_key',{'key_id':row['key_id']},endpoint=vault['management_endpoint'])
            _identity(key,row['key_id'])
            if key.get('vault_id')!=vault['id']:
                raise CleanupError('Source secret key/vault identity mismatch')
            if targets and (vault['compartment_id'] not in scope or key['compartment_id'] not in scope):
                raise CleanupError('Replicated source encryption dependencies outside scope')
        evidence=[]
        for target in targets:
            region=target['target_region']
            if region not in gateway.regions or region==node.region: raise CleanupError('Secret target region unavailable')
            replica,_=gateway.read('vault',region,'get_secret',{'secret_id':node.key}); _identity(replica,node.key)
            info=replica.get('source_region_information')
            expected={'source_region':node.region,'source_vault_id':row['vault_id'],'source_key_id':row['key_id']}
            if replica['compartment_id'] not in scope or replica.get('is_replica') is not True or type(info) is not dict or any(info.get(k)!=v for k,v in expected.items()):
                raise CleanupError('Secret replica owner or source linkage unresolved')
            if not terminal:
                if replica.get('lifecycle_state') not in _ELIGIBLE['Secret']+_PENDING: raise CleanupError('Replica lifecycle state unresolved')
                vault,_=self._vault(gateway,region,target['target_vault_id'])
                key,_=gateway.read('kms_management',region,'get_key',{'key_id':target['target_key_id']},endpoint=vault['management_endpoint']); _identity(key,target['target_key_id'])
                if vault['compartment_id'] not in scope or key['compartment_id'] not in scope or key.get('vault_id')!=vault['id']:
                    raise CleanupError('Secret target vault or key outside scope')
            if terminal and replica.get('lifecycle_state')!='DELETED': raise CleanupError('Regional secret deletion remains unverified')
            member={'id':node.key,'region':region,'compartment_id':replica['compartment_id'],'lifecycle_state':replica.get('lifecycle_state') or '',**expected,**target}
            timestamp=_utc(replica.get('time_of_deletion'))
            if timestamp: member['scheduled_at']=timestamp
            evidence.append(member)
        return targets,evidence

    def _dependencies(self,gateway,node,row,scope,allow_references=False):
        kind=node.resource_type
        if kind in ('Certificate','CertificateAuthority','CaBundle'):
            consumers=self._consumers(gateway,node,scope)
            issued=self._issued(gateway,node,scope) if kind=='CertificateAuthority' else []
            if kind=='CertificateAuthority' and row.get('config_type') not in ('ROOT_CA_GENERATED_INTERNALLY','SUBORDINATE_CA_ISSUED_BY_INTERNAL_CA','ROOT_CA_MANAGED_EXTERNALLY','SUBORDINATE_CA_MANAGED_INTERNALLY_ISSUED_BY_EXTERNAL_CA'):
                raise CleanupError('Certificate authority configuration type unresolved')
            if kind in ('Certificate','CertificateAuthority') and row.get('certificate_revocation_list_details') is not None:
                raise CleanupError('CRL object deletion effects are unproven')
            if not allow_references and (consumers or issued): raise CleanupError('Certificate consumers or issued children remain')
            return [Edge(x,node.key,'Typed certificate consumer') for x in consumers]+[Edge(x,node.key,'Typed issuer relationship') for x in issued]
        if kind=='Vault':
            keys=self._key_set(gateway,node.region,row,scope,node.metadata.get('key_consumers',[]),allow_references)
            if 'cascade_members' in node.metadata and sorted(node.metadata['cascade_members'])!=sorted(keys): raise CleanupError('Vault cascade membership changed')
            return keys
        if kind=='Key':
            vault,_=self._vault(gateway,node.region,row['vault_id']); self._unreplicated(gateway,node.region,vault,row)
            if vault.get('lifecycle_state')!='ACTIVE': raise CleanupError('Vault deletion or transition is already pending')
            consumers=self._key_consumers(gateway,{node.key},scope,node.metadata.get('key_consumers',[]),record_external=allow_references)
            if consumers and not allow_references: raise CleanupError('Live key consumers remain')
            return consumers
        if kind=='Secret': return self._secret_group(gateway,node,row,scope)

    def inspect(self,gateway,node,scope):
        try:
            if node.resource_type not in _CONTRACTS: raise CleanupError('Unsupported scheduled identity')
            row,headers,_=self._read(gateway,node); owner=row['compartment_id']; state=row.get('lifecycle_state') or ''
            if owner not in scope or owner!=node.compartment_id:
                return Observation('moved',owner,state,None,None,'Live ownership changed; refresh report')
            timestamp=_utc(row.get('time_of_deletion'))
            if state=='DELETED':
                if node.resource_type=='Secret': self._secret_group(gateway,node,row,scope,terminal=True)
                return Observation('deleted',owner,state,timestamp,headers.get('etag'),'Positive terminal resource observation')
            if node.resource_type=='Secret' and row.get('is_replica') is not False: raise CleanupError('Replica cannot be independently scheduled')
            if state in _PENDING:
                return Observation('pending',owner,state,timestamp,headers.get('etag'),'Deletion remains pending; unknown UTC schedule' if timestamp is None else 'Service-confirmed deletion schedule remains pending')
            if state not in _ELIGIBLE[node.resource_type]: raise CleanupError('Lifecycle state does not establish scheduling eligibility')
            for key in _FIELDS[node.resource_type]:
                if key in ('replica_details','certificate_revocation_list_details'): continue
                if key in node.metadata and node.metadata[key]!=row.get(key): raise CleanupError('Typed dependency changed; refresh report')
            self._dependencies(gateway,node,row,scope)
            return Observation('present',owner,state,timestamp,headers.get('etag'),'Fresh typed identity, scope and dependencies')
        except Exception:
            return Observation('unresolved',node.compartment_id,'',None,None,'Live identity, schedule, replica scope or dependencies unresolved; refresh report')

    def submit(self,gateway,node,observation,attempt_id):
        if observation.status!='present' or not observation.etag: raise CleanupError('Mutation requires a fresh eligible observation and ETag')
        scope=_scope(gateway); fresh=self.inspect(gateway,node,scope)
        if fresh.status!='present' or fresh.etag!=observation.etag: raise CleanupError('Scheduled resource preflight changed')
        row,headers,endpoint=self._read(gateway,node)
        if headers.get('etag')!=fresh.etag or row['compartment_id']!=node.compartment_id or row['compartment_id'] not in scope or row.get('lifecycle_state') not in _ELIGIBLE[node.resource_type]:
            raise CleanupError('Conditional resource identity changed')
        proof=self._dependencies(gateway,node,row,scope)
        if node.resource_type=='Key' and node.metadata.get('cascade_owner'):
            # Artifact metadata cannot manufacture permission for a member write.
            raise CleanupError('Vault cascade members cannot be scheduled independently')
        service,_,_,operation,parameter,detail,model=_CONTRACTS[node.resource_type]
        params={parameter:node.key,'if_match':fresh.etag,'opc_request_id':attempt_id}
        if model:
            now=datetime.now(timezone.utc); when=scheduled_time(node.resource_type,now)
            if node.resource_type=='Vault':
                for key in proof.values():
                    stamp=_utc(key.get('time_of_deletion'))
                    if key.get('lifecycle_state') in _PENDING and stamp is None: raise CleanupError('Pending key schedule is unknown')
                    if stamp: when=max(when,datetime.fromisoformat(stamp.replace('Z','+00:00')))
                if when>now+timedelta(days=30): raise CleanupError('Existing key schedule exceeds allowed vault window')
            params[detail]=model(time_of_deletion=when)
            if node.resource_type in ('Vault','Key'): params['opc_retry_token']=attempt_id
        _,result_headers=gateway.write(service,node.region,operation,params,endpoint=endpoint)
        confirmed=self.inspect(gateway,node,scope)
        # Never retain the locally requested date as service confirmation.
        evidence={'work_request_id':result_headers['opc-work-request-id']} if result_headers.get('opc-work-request-id') else None
        return Submission(confirmed.status if confirmed.status in ('pending','deleted') else 'unresolved',result_headers.get('opc-request-id'),confirmed.scheduled_at,'Conditional operation submitted; positive terminal verification required',evidence)

    def _source_node(self,gateway,row,region,scope):
        if row.get('is_replica') is False:
            n=_node('Secret',row,region,self)
            targets,evidence=self._secret_group(gateway,n,row,scope)
            return replace(n,metadata=dict(n.metadata,replication_targets=targets,regional_replicas=evidence))
        if row.get('is_replica') is not True: raise CleanupError('Secret replication role is unknown')
        info=row.get('source_region_information')
        if type(info) is not dict or not isinstance(info.get('source_region'),str) or info['source_region'] not in gateway.regions or info['source_region']==region:
            raise CleanupError('Secret source region is unresolved')
        source,_=gateway.read('vault',info['source_region'],'get_secret',{'secret_id':row['id']}); _identity(source,row['id'])
        if source['compartment_id'] not in scope: raise CleanupError('Secret source outside scope')
        n=self._source_node(gateway,source,info['source_region'],scope)
        if region not in [x['region'] for x in n.metadata['regional_replicas']]: raise CleanupError('Replica absent from source target proof')
        return n

    def discover(self,gateway,compartment_id,region):
        scope=_scope(gateway); nodes=[]; edges=[]; probes=[]
        for kind in ('Certificate','CertificateAuthority','CaBundle','Secret'):
            service,listing,operation,_,parameter,_,_=_CONTRACTS[kind]
            try:
                for summary in gateway.items(service,region,listing,{'compartment_id':compartment_id}):
                    _identity(summary,owner=compartment_id)
                    row,_=gateway.read(service,region,operation,{parameter:summary['id']}); _identity(row,summary['id'],compartment_id)
                    n=_node(kind,row,region,self)
                    try:
                        if kind=='Secret':
                            n=self._source_node(gateway,row,region,scope)
                            for member in n.metadata['regional_replicas']:
                                edges.append(Edge(n.key,member['target_key_id'],'Typed secret replica encryption key'))
                                edges.append(Edge(n.key,member['target_vault_id'],'Typed secret replica vault'))
                        else: edges.extend(self._dependencies(gateway,n,row,scope,allow_references=True))
                    except Exception:
                        if kind=='Secret' and row.get('is_replica') is True:
                            n=Node(child_key('secret_replica',region,row['id'],row['id']),'SecretReplica',region,compartment_id,'',row.get('lifecycle_state') or '',self.name,'unresolved',{'source_secret_id':row['id'],'source_region':(row.get('source_region_information') or {}).get('source_region',''),'scheduled_at':_utc(row.get('time_of_deletion'))})
                        n=_blocked(n,'External or unresolved scheduled resource dependency')
                    nodes.append(self.classify(n))
                probes.append(Probe(self.name+':'+kind,region,compartment_id,'complete',''))
            except Exception:
                probes.append(Probe(self.name+':'+kind,region,compartment_id,'failed','Typed service inventory failed'))
        # Keys can live in a different compartment from their vault. Read every
        # visible vault, then query this compartment at its freshly verified endpoint.
        try:
            seen=set()
            for owner in _compartments(gateway):
                for summary in gateway.items('kms_vault',region,'list_vaults',{'compartment_id':owner}):
                    _identity(summary,owner=owner)
                    vault,_=self._vault(gateway,region,summary['id']); _identity(vault,summary['id'],owner)
                    if vault['id'] in seen: raise CleanupError('Duplicate vault identity')
                    seen.add(vault['id']); members=[]; vault_node=_node('Vault',vault,region,self)
                    try:
                        if owner in scope:
                            members=list(self._key_set(gateway,region,vault,scope,allow_references=True).values())
                            vault_node=replace(vault_node,metadata=dict(vault_node.metadata,cascade_members=sorted(x['id'] for x in members),cascade_verified=True,key_consumers=[c for x in members for c in x['__key_consumers']]))
                            if self._outside_consumers(vault_node.metadata['key_consumers'],scope): vault_node=_blocked(vault_node,'External typed key consumer blocks vault cascade')
                    except Exception:
                        vault_node=_blocked(vault_node,'Vault cascade identity, count or replication proof unresolved')
                    if owner==compartment_id: nodes.append(self.classify(vault_node))
                    if vault.get('lifecycle_state')=='DELETED': continue
                    for key_summary in gateway.items('kms_management',region,'list_keys',{'compartment_id':compartment_id},endpoint=vault['management_endpoint']):
                        _identity(key_summary,owner=compartment_id)
                        row,_=gateway.read('kms_management',region,'get_key',{'key_id':key_summary['id']},endpoint=vault['management_endpoint']); _identity(row,key_summary['id'],compartment_id)
                        if row.get('vault_id')!=vault['id']: raise CleanupError('Key actual vault mismatch')
                        key_node=_node('Key',row,region,self)
                        try:
                            self._unreplicated(gateway,region,vault,row)
                            consumers=self._key_consumers(gateway,{row['id']},scope,record_external=True)
                            key_node=replace(key_node,metadata=dict(key_node.metadata,key_consumers=consumers))
                            if self._outside_consumers(consumers,scope): key_node=_blocked(key_node,'External typed key consumer blocks deletion')
                            edges.extend(Edge(c['id'],row['id'],'Typed KMS consumer') for c in consumers)
                        except Exception: key_node=_blocked(key_node,'Key replication or reverse consumer identity unresolved')
                        if not vault_node.blockers and owner in scope and row['id'] in [x['id'] for x in members]:
                            key_node=replace(key_node,metadata=dict(key_node.metadata,cascade_owner=vault['id'],cascade_verified=True))
                        nodes.append(self.classify(key_node))
                        if owner in scope: edges.append(Edge(row['id'],vault['id'],'Typed vault key ownership'))
            probes.append(Probe(self.name+':KMS',region,compartment_id,'complete','Supported reverse key scans: volumes, boot volumes, backups, buckets, CAs, secrets and secret replica targets across subscribed regions; OCI has no universal key consumer inventory'))
        except Exception:
            probes.append(Probe(self.name+':KMS',region,compartment_id,'failed','Vault endpoint or key inventory failed'))
        return nodes,edges,probes

    def refresh_node(self,gateway,node,previous,scope):
        """Keep known regional and consumer identities until positive live proof.

        New list coverage cannot erase an old reverse reference or a same-OCID
        secret replica. Reestablish the proof using the exact typed GET contracts.
        """
        fields=('replication_targets','regional_replicas') if node.resource_type=='Secret' else ('key_consumers',) if node.resource_type in ('Key','Vault') else ()
        metadata=dict(node.metadata)
        for field in fields:
            old=previous.metadata.get(field,[])
            if old:
                # A current target-set change must be reviewed. For reverse key
                # consumers retain the union and inspect each known old identity.
                if field=='key_consumers': metadata[field]=old+[x for x in metadata.get(field,[]) if x not in old]
                elif field=='replication_targets': metadata[field]=old
                elif not metadata.get(field): metadata[field]=old
        renewed=replace(node,metadata=metadata)
        if not fields: return renewed
        try:
            row,_,_=self._read(gateway,renewed); _identity(row,node.key,node.compartment_id)
            if row['compartment_id'] not in scope: raise CleanupError('Refreshed resource moved outside scope')
            if node.resource_type=='Secret':
                targets,evidence=self._secret_group(gateway,renewed,row,scope,terminal=row.get('lifecycle_state')=='DELETED')
                metadata.update(replication_targets=targets,regional_replicas=evidence)
            elif row.get('lifecycle_state')!='DELETED':
                proof=self._dependencies(gateway,renewed,row,scope,allow_references=True)
                metadata['key_consumers']=[c for key in proof.values() for c in key['__key_consumers']] if node.resource_type=='Vault' else proof
            if node.resource_type in ('Key','Vault') and self._outside_consumers(metadata.get('key_consumers',[]),scope):
                return _blocked(replace(renewed,metadata=metadata),'Historical external key consumer remains unresolved')
            return replace(renewed,metadata=metadata)
        except Exception:
            return _blocked(renewed,'Historical regional or reverse consumer evidence remains unresolved')

    def reconcile_record(self,gateway,node,scope,record):
        """Task 10: inspect all scheduled nodes before rendering or retrying.

        Preserve attempts/errors/history; only live confirmation populates schedule.
        This hook does not write a state file or submit an operation.
        """
        observation=self.inspect(gateway,node,scope)
        updated=dict(record,status=observation.status,lifecycle_state=observation.lifecycle_state)
        if observation.scheduled_at is not None:
            updated['scheduled_at']=observation.scheduled_at
        elif observation.status in ('present','pending','deleted'):
            old=record.get('scheduled_at')
            if old is not None:
                history=record.get('schedule_history',[])
                if type(history) is not list: raise CleanupError('Schedule history is malformed')
                updated['schedule_history']=list(history)+[{'scheduled_at':old,'status':record.get('status','unknown'),'lifecycle_state':record.get('lifecycle_state','')} ]
            # Explicit None is a successful current observation of an unknown
            # schedule, distinct from an unresolved read that retains history.
            updated['scheduled_at']=None
        return updated
