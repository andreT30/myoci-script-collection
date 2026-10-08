"""Behavioral offline gateway with explicit fixtures and mutable resource state."""
from dataclasses import replace
from datetime import datetime, timezone
from copy import deepcopy

from compartment_cleanup.gateway import GatewayError
from compartment_cleanup.model import CleanupError


class Simulator:
    def __init__(self, tenancy_id='tenancy', home_region='region', compartments=None):
        self.tenancy_id = tenancy_id
        self.bootstrap_region = home_region
        self.home_region = home_region
        self.regions = [home_region]
        self.compartment_links = dict(compartments or {})
        self.resources = {}
        self.events = []
        self.pages = {}
        self.responses = {}
        self.permission_failures = {}
        self.work_requests = {}
        self.scheduled = {}
        self.now = datetime(2026, 10, 8, tzinfo=timezone.utc)

    def add(self, node):
        self.resources[node.key] = node

    def schedule(self, key, when, request_id=None):
        if when.tzinfo is None:
            raise CleanupError('Simulator schedule requires timezone')
        self.resources[key] = replace(self.resources[key], lifecycle_state='PENDING_DELETION')
        self.scheduled[key] = (when, request_id)
        if request_id:
            self.work_requests[request_id] = {'status': 'IN_PROGRESS', 'resources': [key], 'errors': []}

    def advance(self, when):
        if when.tzinfo is None or when < self.now:
            raise CleanupError('Simulator clock must advance with timezone')
        self.now = when
        for key, (scheduled_at, request_id) in list(self.scheduled.items()):
            if scheduled_at <= when:
                self.resources[key] = replace(self.resources[key], lifecycle_state='DELETED')
                self.events.append(('completed', key))
                if request_id:
                    self.work_requests[request_id]['status'] = 'SUCCEEDED'
                del self.scheduled[key]

    def set_pages(self, service, region, operation, pages):
        self.pages[(service, region, operation)] = deepcopy(pages)

    def deny(self, service, region, operation, status=403):
        self.permission_failures[(service, region, operation)] = status

    def _event(self, mode, service, region, operation, params, endpoint):
        self.events.append((mode, service, region, operation, deepcopy(params), endpoint))
        status = self.permission_failures.get((service, region, operation))
        if status:
            raise GatewayError(service, operation, status, 'NotAuthorizedOrNotFound')

    def read(self, service, region, operation, params, endpoint=None):
        self._event('read', service, region, operation, params, endpoint)
        fixture = self.responses.get((service, region, operation))
        if fixture is not None:
            if isinstance(fixture, Exception):
                raise fixture
            return deepcopy(fixture)
        if operation == 'get_work_request':
            return deepcopy(self.work_requests[params['work_request_id']]), {}
        if service == 'identity' and operation == 'get_compartment':
            key = params['compartment_id']
            if key in self.compartment_links:
                return {'id': key, 'compartment_id': self.compartment_links[key], 'lifecycle_state': 'ACTIVE'}, {}
        key = next((v for k, v in params.items() if k.endswith('_id') and v in self.resources), None)
        if key is not None:
            node = self.resources[key]
            return dict(deepcopy(node.metadata), id=node.key, compartment_id=node.compartment_id,
                        lifecycle_state=node.lifecycle_state, display_name=node.display_name), {}
        raise GatewayError(service, operation, 404, 'NotAuthorizedOrNotFound')

    def items(self, service, region, operation, params, endpoint=None):
        self._event('items', service, region, operation, params, endpoint)
        fixtures = self.pages.get((service, region, operation))
        if fixtures is not None:
            values = []
            for page in fixtures:
                if isinstance(page, Exception):
                    raise page
                data, _ = page
                values.extend(deepcopy(data))
            return values
        if service == 'identity' and operation == 'list_region_subscriptions':
            return [{'region_name': r, 'is_home_region': r == self.home_region, 'status': 'READY'} for r in self.regions]
        if service == 'identity' and operation == 'list_compartments':
            return [{'id': key, 'compartment_id': parent, 'lifecycle_state': 'ACTIVE'}
                    for key, parent in self.compartment_links.items()
                    if params.get('compartment_id_in_subtree') or parent == params['compartment_id']]
        raise CleanupError('Simulator list requires an explicit page fixture')

    def write(self, service, region, operation, params, endpoint=None):
        self._event('write', service, region, operation, params, endpoint)
        fixture = self.responses.get((service, region, operation))
        if fixture is not None:
            if isinstance(fixture, Exception):
                raise fixture
            return deepcopy(fixture)
        raise CleanupError('Simulator mutation requires an explicit response fixture')

    def discover_scope(self, parent_id):
        if parent_id == self.tenancy_id or parent_id not in self.compartment_links:
            raise CleanupError('Simulator parent is outside tenancy')
        scope = {parent_id}
        pending = [parent_id]
        while pending:
            current = pending.pop()
            for key, parent in self.compartment_links.items():
                if parent == current and key not in scope:
                    scope.add(key)
                    pending.append(key)
        return self.tenancy_id, self.home_region, list(self.regions), {
            key: self.compartment_links[key] for key in scope}


class StorageSimulator(Simulator):
    """Bucket-owned metadata only; writes enforce identity and mutate inventory."""
    def __init__(self):
        super().__init__()
        self.cleanup_scope = {'parent', 'child'}
        self.namespace = 'canonical'
        self.bucket = {'id': 'ocid1.bucket.oc1..original', 'namespace': self.namespace,
                       'name': 'bucket', 'compartment_id': 'child',
                       'time_created': '2026-10-01T00:00:00+00:00', 'etag': 'bucket-etag',
                       'versioning': 'Disabled', 'replication_enabled': False,
                       'is_read_only': False, 'object_lifecycle_policy_etag': None}
        self.inventory = {op: [] for op in ('list_objects', 'list_object_versions',
            'list_multipart_uploads', 'list_preauthenticated_requests',
            'list_retention_rules', 'list_replication_policies', 'list_replication_sources')}
        self.policy = {'items': [], 'time_created': '2026-10-01T00:00:00+00:00'}
        self.write_headers = {'__http_status__': 204}
        self.destination = None

    def read(self, service, region, operation, params, endpoint=None):
        self._event('read', service, region, operation, params, endpoint)
        if operation == 'get_namespace': return self.namespace, {'__http_status__': 200}
        if params.get('namespace_name') != self.namespace: raise CleanupError('Wrong namespace')
        if operation == 'get_bucket':
            bucket = self.bucket if params['bucket_name'] == 'bucket' else self.destination
            if not bucket: raise GatewayError(service, operation, 404)
            return deepcopy(bucket), {'etag': bucket['etag'], '__http_status__': 200}
        if operation == 'get_object_lifecycle_policy':
            if not self.bucket['object_lifecycle_policy_etag']: raise GatewayError(service, operation, 404)
            return deepcopy(self.policy), {'etag': self.bucket['object_lifecycle_policy_etag']}
        if operation == 'get_retention_rule':
            row = next(r for r in self.inventory['list_retention_rules'] if r['id'] == params['retention_rule_id'])
            return deepcopy(row), {'etag': row['etag']}
        if operation == 'head_object':
            rows = self.inventory['list_object_versions'] if 'version_id' in params else self.inventory['list_objects']
            row = next((r for r in rows if r['name'] == params['object_name'] and
                ('version_id' not in params or r['version_id'] == params['version_id'])), None)
            if not row or row.get('is_delete_marker'): raise GatewayError(service, operation, 404)
            return None, {'etag': row['etag'], 'version-id': row.get('version_id'), '__http_status__': 200}
        raise CleanupError('Unexpected storage read')

    def items(self, service, region, operation, params, endpoint=None):
        if (service, region, operation) in self.pages:
            return super().items(service, region, operation, params, endpoint)
        self._event('items', service, region, operation, params, endpoint)
        if params.get('namespace_name') != self.namespace: raise CleanupError('Wrong namespace')
        if operation == 'list_buckets': return [{'name': 'bucket'}] if self.bucket else []
        return deepcopy(self.inventory[operation])

    def write(self, service, region, operation, params, endpoint=None):
        self._event('write', service, region, operation, params, endpoint)
        if params.get('namespace_name') != self.namespace or params.get('bucket_name') != 'bucket':
            raise CleanupError('Wrong write identity')
        headers = deepcopy(self.write_headers)
        if operation == 'delete_object':
            op = 'list_object_versions' if 'version_id' in params else 'list_objects'
            row = next(r for r in self.inventory[op] if r['name'] == params['object_name'] and
                ('version_id' not in params or r['version_id'] == params['version_id']))
            if params.get('if_match') != row['etag']: raise GatewayError(service, operation, 412)
            self.inventory[op].remove(row)
            if 'version_id' in params: headers['version-id'] = params['version_id']
        elif operation == 'abort_multipart_upload':
            rows = self.inventory['list_multipart_uploads']
            rows.remove(next(r for r in rows if r['upload_id'] == params['upload_id'] and r['object'] == params['object_name']))
        elif operation == 'delete_preauthenticated_request':
            rows = self.inventory['list_preauthenticated_requests']
            rows.remove(next(r for r in rows if r['id'] == params['par_id']))
        elif operation == 'delete_object_lifecycle_policy':
            if params['if_match'] != self.bucket['object_lifecycle_policy_etag']: raise GatewayError(service, operation, 412)
            self.bucket['object_lifecycle_policy_etag'] = None
        elif operation == 'delete_retention_rule':
            rows = self.inventory['list_retention_rules']
            row = next(r for r in rows if r['id'] == params['retention_rule_id'])
            if params['if_match'] != row['etag']: raise GatewayError(service, operation, 412)
            rows.remove(row)
        elif operation == 'delete_bucket':
            if any(self.inventory.values()) or self.bucket['object_lifecycle_policy_etag']: raise GatewayError(service, operation, 409)
            if params['if_match'] != self.bucket['etag']: raise GatewayError(service, operation, 412)
            self.bucket = None
        elif operation == 'batch_delete_objects':
            deleted=[]
            for item in params['batch_delete_objects_details'].objects:
                row=next(r for r in self.inventory['list_objects'] if r['name']==item.object_name)
                if row['etag']!=item.if_match: raise GatewayError(service, operation, 412)
                self.inventory['list_objects'].remove(row)
                deleted.append({'object_name':item.object_name,'time_last_modified':self.now.isoformat()})
            return {'deleted':deleted,'failed':[]}, headers
        else: raise CleanupError('Unexpected storage write')
        return None, headers
