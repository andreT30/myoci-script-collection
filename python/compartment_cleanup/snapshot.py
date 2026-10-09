"""Read-only inventories shared within one discovery; never mutation preflight."""
from copy import deepcopy
import json

from .gateway import _normalize
from .model import CleanupError


class DiscoverySnapshot:
    def __init__(self, gateway):
        self._gateway = gateway
        self._results = {}
        self._failures = {}

    def __getattr__(self, name):
        return getattr(self._gateway, name)

    def _fetch(self, mode, service, region, operation, params, endpoint):
        key = (mode, service, region, operation, endpoint,
               json.dumps(_normalize(params), sort_keys=True, separators=(',', ':')))
        if key in self._failures:
            raise self._failures[key]
        if key not in self._results:
            try:
                result = getattr(self._gateway, mode)(service, region, operation, params, endpoint)
            except CleanupError as error:
                # A failed/denied inventory stays failed for this discovery.
                # Never substitute an empty list or retain partial pages.
                self._failures[key] = error
                raise
            self._results[key] = deepcopy(result)
        return deepcopy(self._results[key])

    def read(self, service, region, operation, params, endpoint=None):
        return self._fetch('read', service, region, operation, params, endpoint)

    def items(self, service, region, operation, params, endpoint=None):
        return self._fetch('items', service, region, operation, params, endpoint)

    def write(self, *args, **kwargs):
        raise CleanupError('Discovery snapshots cannot submit OCI mutations')
