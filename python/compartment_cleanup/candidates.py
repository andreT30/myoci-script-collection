"""Discovery restricted to Search seeds and their explicitly related children.

This view is never used to authorize a mutation or certify tenancy-wide absence.
"""
from .snapshot import DiscoverySnapshot
from .model import Node, CleanupError


def _contracts():
    from .handlers.core import _POLICY, _COMPUTE, _VOLUMES
    from .handlers.network import NETWORK_OPERATIONS, _DNS
    from .handlers.scheduled import _CONTRACTS as scheduled
    from .handlers.load_balancers import _CONTRACTS as balancers
    from .handlers.logging_analytics import _CONTRACTS as logging
    lists, reads = {}, {}
    for contracts in (_POLICY, _COMPUTE, _VOLUMES, scheduled, balancers, logging):
        for kind, contract in contracts.items():
            service, listing, reading = contract[:3]
            if listing:
                lists[service, listing] = kind
            reads[service, reading] = kind
    for kind, (listing, reading, _, _) in NETWORK_OPERATIONS.items():
        lists['network', listing] = kind
        reads['network', reading] = kind
    for kind, (reading, _) in _DNS.items():
        reads['dns', reading] = kind
    lists.update({('network', 'list_vlans'): 'Vlan',
                  ('network', 'list_drg_attachments'): 'DrgAttachment',
                  ('dns', 'list_resolvers'): 'Resolver',
                  ('object_storage', 'list_buckets'): 'Bucket',
                  ('compute_management', 'list_instance_pools'): 'InstancePool',
                  ('container_engine', 'list_clusters'): 'Cluster',
                  ('container_engine', 'list_node_pools'): 'NodePool',
                  ('network', 'list_public_ips'): 'PublicIp'})
    reads['object_storage', 'get_bucket'] = 'Bucket'
    return lists, reads


class CandidateSnapshot(DiscoverySnapshot):
    search_driven = True

    def __init__(self, gateway, seeds):
        super().__init__(gateway)
        self.candidates = {}
        for node in seeds:
            if node.resource_type == 'Compartment':
                continue
            old = next((n for n in self.candidates.values() if n.key == node.key), None)
            if old and (old.resource_type, old.compartment_id) != (
                    node.resource_type, node.compartment_id):
                raise CleanupError('Candidate identity changed; resolve conflicting saved scope')
            # Search may return a global identity in several regional indexes.
            # Keep each regional candidate until authoritative rows are merged.
            self.candidates[node.key, node.region] = node
        self._lists, self._reads = _contracts()

    def has_kind(self, kind, region=None):
        return any(n.resource_type == kind and (region is None or n.region == region)
                   for n in self.candidates.values())

    def _selected(self, kind, region, owner=None):
        return {n.key for n in self.candidates.values()
                if n.resource_type == kind and n.region == region
                and (owner is None or n.compartment_id == owner)}

    def _record(self, kind, region, row):
        if (isinstance(row, dict) and isinstance(row.get('id'), str)
                and row.get('compartment_id') in self.cleanup_scope):
            old = next((n for n in self.candidates.values() if n.key == row['id']), None)
            if old and (old.resource_type, old.compartment_id) != (
                    kind, row['compartment_id']):
                raise CleanupError('Candidate identity changed during mapping')
            self.candidates[row['id'], region] = Node(
                row['id'], kind, region, row['compartment_id'],
                row.get('display_name') or row.get('name') or '',
                row.get('lifecycle_state') or '', '', 'unresolved', {})

    def read(self, service, region, operation, params, endpoint=None):
        data, headers = super().read(service, region, operation, params, endpoint)
        kind = self._reads.get((service, operation))
        if kind:
            if kind == 'Bucket':
                expected = {n.key for n in self.candidates.values()
                            if n.resource_type == 'Bucket' and n.region == region
                            and n.display_name == params.get('bucket_name')}
                if not expected or not isinstance(data, dict) or data.get('id') not in expected:
                    raise CleanupError('Bucket identity does not match Search candidate')
            self._record(kind, region, data)
        return data, headers

    def _related(self, kind, region, owner, params, endpoint):
        if kind in ('Certificate', 'CertificateAuthority'):
            return params.get('issuer_certificate_authority_id') in self._selected('CertificateAuthority', region)
        if kind in ('VnicAttachment', 'VolumeAttachment', 'BootVolumeAttachment'):
            roots = {'VnicAttachment': ('Instance',),
                     'VolumeAttachment': ('Instance', 'Volume'),
                     'BootVolumeAttachment': ('Instance', 'BootVolume')}[kind]
            return any(self._selected(k, region) for k in roots)
        if kind == 'PublicIp':
            return bool(self._selected('Instance', region))
        if kind in ('Subnet', 'InternetGateway', 'NatGateway', 'ServiceGateway',
                    'LocalPeeringGateway', 'RouteTable', 'SecurityList', 'DhcpOptions',
                    'NetworkSecurityGroup', 'Vlan', 'DrgAttachment', 'Resolver'):
            return bool(self._selected('Vcn', region))
        if kind == 'Key' and endpoint:
            vault = self._vault_endpoints.get((region, endpoint))
            return vault in self._selected('Vault', region)
        return False

    def items(self, service, region, operation, params, endpoint=None):
        owner = params.get('compartment_id')
        # No blind enumeration of unrelated compartments, even inside a
        # selected handler's existing reverse-dependency loops.
        if owner and owner not in self.cleanup_scope:
            if (service, operation) not in (('identity', 'list_availability_domains'),
                                           ('identity', 'list_compartments'),
                                           ('identity', 'list_region_subscriptions')):
                return []
        kind = self._lists.get((service, operation))
        if kind:
            selected = self._selected(kind, region, owner)
            related = self._related(kind, region, owner, params, endpoint)
            if not selected and not related:
                return []
            rows = super().items(service, region, operation, params, endpoint)
            if kind == 'Bucket':
                # BucketSummary has a name, not an OCID. GET below supplies and
                # verifies the canonical OCID before the handler emits nodes.
                names = {n.display_name for n in self.candidates.values()
                         if n.key in selected and n.display_name}
                rows = [r for r in rows if r.get('name') in names]
                if selected and (len(names) != len(selected) or len(rows) != len(names)):
                    raise CleanupError('Search bucket names could not be corroborated')
            elif related and kind in ('Certificate', 'CertificateAuthority'):
                issuer = params.get('issuer_certificate_authority_id')
                rows = [r for r in rows if r.get('issuer_certificate_authority_id') == issuer]
            elif not related:
                rows = [r for r in rows if r.get('id') in selected]
            elif kind == 'PublicIp':
                private_ips = self._selected('PrivateIp', region)
                rows = [r for r in rows if r.get('id') in selected
                        or r.get('private_ip_id') in private_ips
                        or r.get('assigned_entity_id') in private_ips]
            elif kind in ('VnicAttachment', 'VolumeAttachment', 'BootVolumeAttachment'):
                instances = self._selected('Instance', region)
                volumes = self._selected('Volume', region) | self._selected('BootVolume', region)
                rows = [r for r in rows if r.get('id') in selected
                        or r.get('instance_id') in instances
                        or r.get('volume_id') in volumes or r.get('boot_volume_id') in volumes]
            elif kind in ('Subnet', 'InternetGateway', 'NatGateway', 'ServiceGateway',
                          'LocalPeeringGateway', 'RouteTable', 'SecurityList', 'DhcpOptions',
                          'NetworkSecurityGroup', 'Vlan', 'DrgAttachment', 'Resolver'):
                vcns = self._selected('Vcn', region)
                rows = [r for r in rows if r.get('id') in selected or r.get('vcn_id') in vcns
                        or r.get('attached_vcn_id') in vcns
                        or (r.get('network_details') or {}).get('id') in vcns]
            for row in rows:
                self._record(kind, region, row)
            return rows
        # Child inventories require an explicit parent identity, bucket, or
        # namespace. Remaining operations are fixed, code-defined gateway APIs.
        return super().items(service, region, operation, params, endpoint)
