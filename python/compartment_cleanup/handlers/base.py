"""Code-defined service dispatch; artifact fields never select an SDK operation."""
from dataclasses import replace

from ..model import CleanupError, Node, Observation, Submission


class Handler:
    """Service implementations declare their typed metadata and reference allowlists.

    bulk_resource_types maps a known resource type to the exact IAM catalog name.
    bulk_metadata builds required identifiers from freshly discovered typed fields;
    it must never infer identifiers from display names. Task 8 consumes this hook.
    """
    late_action = False
    name = ''
    resource_types = ()
    action = 'unresolved'
    metadata_keys = ()
    reference_fields = ()
    # Verified non-cascading outbound references only; outside resources persist.
    retained_reference_fields = ()
    bulk_resource_types = {}

    def discover(self, gateway, compartment_id: str, region: str):
        raise NotImplementedError

    def inspect(self, gateway, node: Node, scope: set[str]) -> Observation:
        return Observation('unresolved', node.compartment_id, node.lifecycle_state,
                           None, None, 'No authoritative inspection is implemented')

    def submit(self, gateway, node: Node, observation: Observation, attempt_id: str) -> Submission:
        raise CleanupError('No resource operation is implemented')

    def classify(self, node: Node) -> Node:
        return replace(node, handler=self.name, action=self.action)

    def bulk_metadata(self, node: Node, required: tuple[str, ...]) -> dict:
        return {}


class Registry:
    def __init__(self, handlers: dict[str, Handler] | None = None):
        self.handlers = dict(handlers or {})
        self._types = {}
        for name, handler in self.handlers.items():
            if name != handler.name or not name:
                raise CleanupError('Handler registration name mismatch')
            for resource_type in handler.resource_types:
                if resource_type in self._types:
                    raise CleanupError('Duplicate handler resource type')
                self._types[resource_type] = handler

    def handler_for(self, node: Node) -> Handler | None:
        return self._types.get(node.resource_type)

    def classify(self, node: Node) -> Node:
        handler = self.handler_for(node)
        if handler is None:
            return replace(node, handler='', action='unresolved', metadata={},
                           blockers=tuple(sorted(set(node.blockers + ('Unsupported resource type or unresolved dependencies',)))))
        # Only code-defined handler policy selects an operation. Caller-supplied
        # handler/action/bulk metadata do not influence dispatch.
        safe = replace(node, handler=handler.name, action=handler.action,
                       metadata={k:v for k,v in node.metadata.items() if k in handler.metadata_keys})
        return handler.classify(safe)
