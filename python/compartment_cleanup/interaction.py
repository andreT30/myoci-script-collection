"""Terminal-only, exact confirmations for resource scans and deletion."""
from .reporting import _display


def accepted_yes(*, stdin, stderr, prompt: str) -> bool:
    """Refusal, redirected input and interrupted reads never authorize work."""
    if not stdin.isatty():
        stderr.write('An interactive terminal is required; operation cancelled.\n')
        stderr.flush()
        return False
    stderr.write(prompt)
    stderr.flush()
    try:
        return stdin.readline().rstrip('\r\n') == 'YES'
    except (EOFError, KeyboardInterrupt):
        return False


def confirm_scan(parent_id: str, *, stdin, stderr) -> bool:
    return accepted_yes(stdin=stdin, stderr=stderr, prompt=(
        f'We are about to scan compartment {_display(parent_id)} and its descendants for resources to delete.\n'
        'The supplied parent compartment will be retained.\n'
        'Do you want to proceed? Type YES: '))


def confirm_delete(parent_id: str, *, stdin, stderr) -> bool:
    return accepted_yes(stdin=stdin, stderr=stderr, prompt=(
        f'YOU ARE ABOUT TO DELETE RESOURCES UNDER COMPARTMENT {_display(parent_id)}, INCLUDING DESCENDANT COMPARTMENTS.\n'
        'THE SUPPLIED PARENT COMPARTMENT WILL BE RETAINED.\n'
        'DO YOU WISH TO PROCEED? TYPE YES: '))


def confirm_delete_final(plan, *, stdin, stderr) -> bool:
    return accepted_yes(stdin=stdin, stderr=stderr, prompt=(
        'ARE YOU SURE? THESE ACTIONS CAN PERMANENTLY DELETE RESOURCES.\n'
        'TYPE YES AGAIN: '))


class TerminalInteraction:
    """Interactive decisions for dependency handling in the current terminal."""

    def __init__(self, stdin=None, stderr=None):
        import sys
        self.stdin = sys.stdin if stdin is None else stdin
        self.stderr = sys.stderr if stderr is None else stderr

    def show(self, message):
        self.stderr.write(_display(message) + '\n')
        self.stderr.flush()

    def choose_dependency(self, node, findings):
        if not self.stdin.isatty():
            self.show('An interactive terminal is required; stopping cleanup.')
            return 'stop'
        self.stderr.write('Handle supported dependencies, skip this target, or stop? Type handle / skip / stop: ')
        self.stderr.flush()
        try:
            answer = self.stdin.readline().rstrip('\r\n')
        except (EOFError, KeyboardInterrupt):
            return 'stop'
        return answer if answer in {'handle', 'skip', 'stop'} else 'stop'

    def confirm_targets(self, nodes):
        nodes = list(nodes)
        if not nodes:
            return False
        self.show('Additional deletion targets:')
        for node in nodes:
            self.show(f'{node.display_name or node.key} | {node.resource_type} | {node.region}')
            self.show(f'OCID: {node.key}')
            self.show(f'Owner: {node.compartment_id}')
            self.show(f'Action: {node.handler} / {node.action}')
            for effect in node.metadata.get('effects', ()):
                if isinstance(effect, str):
                    self.show('Effect: ' + effect)
            for volume in node.metadata.get('preserved_volume_ids', ()):
                if isinstance(volume, str):
                    self.show('Volume preserved by instance termination: ' + volume)
        return accepted_yes(stdin=self.stdin, stderr=self.stderr, prompt=(
            'These additional targets may be permanently deleted. Type YES to include them: '))

    def confirm_removed(self, nodes):
        self.show('These resources could not be verified by their resource APIs.')
        self.show('An empty Search result is not a deletion guarantee.')
        self.show('Confirm only if you know every listed resource is already deleted.')
        self.show('This records your acknowledgement locally and continues; it submits no OCI deletion.')
        for node in nodes:
            self.show(f'{node.display_name or node.key} | {node.resource_type} | {node.region}')
            self.show('OCID: ' + node.key)
            self.show('Owner: ' + node.compartment_id)
        return accepted_yes(stdin=self.stdin, stderr=self.stderr, prompt=(
            'Are ALL listed resources already deleted? Type YES to record this and continue, or press Enter to keep them unresolved: '))
