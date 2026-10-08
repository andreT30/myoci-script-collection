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
