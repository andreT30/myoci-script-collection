"""Explicit read-only report and guarded deletion commands."""
import argparse
from datetime import datetime, timezone
import math
from pathlib import Path
from dataclasses import replace
import shutil
import re
import sys

from .discovery import discover
from .inventory import collect_inventory, reconcile_inventory_state
from .guided import execute_guided
from .executor import cleanup_result, preserve_report_members, reconcile_report
from .gateway import build_gateway, discover_scope
from .graph import validate_scope
from .interaction import confirm_scan, confirm_delete, confirm_delete_final, TerminalInteraction
from .handlers.base import Registry
from .handlers.core import BlockBootVolumes, ComputeInstances, IAMPolicies
from .handlers.network import Networks, RoutePreparations
from .handlers.storage import Storage
from .handlers.scheduled import ScheduledResources
from .handlers.logging_analytics import LoggingAnalytics
from .handlers.load_balancers import LoadBalancers
from .model import CleanupError
from .reporting import render_report, render_terminal_summary, _display
from .store import Workspace, reconcile_state


PRESERVE = 'These commands create local files. Preserve the entire work directory until cleanup is finished.'


def _progress(message):
    timestamp = datetime.now(timezone.utc).strftime('%H:%M:%S UTC')
    safe = ''.join(c if c.isprintable() else '?' for c in str(message))
    print(f'[{timestamp}] {safe}', file=sys.stderr, flush=True)



def _sdk_progress(verbose):
    """Show region changes, failed calls and calls taking at least ten seconds."""
    last_region = None

    def progress(message):
        nonlocal last_region
        if verbose:
            _progress(message)
            return
        match = re.match(r'(?:Starting|Completed|Failed) (?:read|write) [^ ]+ in ([^ ]+)', message)
        if match and match[1] != last_region:
            last_region = match[1]
            _progress('Region: ' + last_region)
        if message.startswith('Starting '):
            return
        if message.startswith('Completed '):
            elapsed = re.search(r' after ([0-9.]+)s', message)
            if not elapsed or float(elapsed[1]) < 10:
                return
        _progress(message)

    return progress


def _terminal_report(plan, state, verbose):
    return render_report(plan, state) if verbose else render_terminal_summary(
        plan, state, width=shutil.get_terminal_size((100, 24)).columns)

def build_registry():
    handlers = [IAMPolicies(), BlockBootVolumes(), ComputeInstances(), Networks(),
                RoutePreparations(), Storage(), ScheduledResources(),
                LoggingAnalytics(), LoadBalancers()]
    return Registry({handler.name: handler for handler in handlers})


def _positive_seconds(value):
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError('wait seconds must be positive and finite') from None
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError('wait seconds must be positive and finite')
    return seconds


def _parser():
    parser = argparse.ArgumentParser(description='Clean a compartment tree; retain the supplied parent.',
                                     epilog=PRESERVE)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--report', action='store_true', help='read OCI and write a local plan/report')
    modes.add_argument('--delete', action='store_true', help='execute the saved plan after fresh scope checks')
    parser.add_argument('--exhaustive-discovery', action='store_true',
                        help='report only: scan all implemented services, including resources absent from Search (slow)')
    parser.add_argument('--verbose', action='store_true', help='show detailed OCI call progress and the full report')
    parser.add_argument('--compartment-id', required=True, help='retained parent compartment OCID')
    parser.add_argument('--work-dir', required=True, help='durable plan, action history and report directory')
    parser.add_argument('--confirm-parent', help='required in delete mode; exact retained parent OCID')
    parser.add_argument('--auth', choices=('api_key', 'instance_principal'), default='api_key')
    parser.add_argument('--config-file', default='~/.oci/config')
    parser.add_argument('--profile', default='DEFAULT')
    parser.add_argument('--bootstrap-region', help='initial authenticated region; all subscribed regions are discovered')
    parser.add_argument('--wait-seconds', type=_positive_seconds, default=300,
                        help='positive finite asynchronous wait budget (default: 300); rerun for multi-day schedules')
    return parser


def _artifacts(workspace):
    print(PRESERVE)
    for name in ('plan.json', 'state.json', 'report.txt', '.lock'):
        print(f'{name}: {_display(workspace.path / name)}')


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
        if not re.fullmatch(r'ocid1\.compartment\.[a-z0-9]+\.[a-z0-9.-]*\.[A-Za-z0-9_-]+', args.compartment_id):
            parser.error('invalid retained compartment OCID')
        if args.delete and args.confirm_parent != args.compartment_id:
            parser.error('--delete requires --confirm-parent exactly matching --compartment-id')
        if args.delete and args.exhaustive_discovery:
            parser.error('--exhaustive-discovery is available only with --report')
    except SystemExit as error:
        return int(error.code)
    print('Operation: ' + ('delete' if args.delete else 'report'), file=sys.stderr)
    print('Retained parent: ' + _display(args.compartment_id), file=sys.stderr)
    print('Authentication: ' + args.auth + (('; profile: ' + _display(args.profile)) if args.auth == 'api_key' else ''), file=sys.stderr)
    print('Work directory: ' + _display(str(Path(args.work_dir).expanduser())), file=sys.stderr)
    confirm = confirm_delete if args.delete else confirm_scan
    if not confirm(args.compartment_id, stdin=sys.stdin, stderr=sys.stderr):
        print('Operation cancelled.', file=sys.stderr)
        return 1
    workspace = Workspace(Path(args.work_dir).expanduser())
    try:
        with workspace.locked():
            present = [(workspace.path / name).exists() or (workspace.path / name).is_symlink()
                       for name in ('plan.json', 'state.json')]
            if args.delete or any(present):
                if not all(present):
                    raise CleanupError('Both plan.json and state.json are required; preserve the entire work directory')
                plan, state = workspace.load(args.compartment_id)
            else:
                plan = state = None
            _progress('Loading OCI authentication')
            gateway = build_gateway(args.auth, str(Path(args.config_file).expanduser()),
                                    args.profile, args.bootstrap_region)
            gateway.progress = _sdk_progress(args.verbose)
            registry = build_registry()
            if args.report:
                _progress('Discovering resources: ' + ('exhaustive service scans' if args.exhaustive_discovery
                          else 'Search inventory metadata'))
                if args.exhaustive_discovery:
                    previous = reconcile_report(plan, state, workspace, gateway, registry) if plan is not None else None
                    fresh = discover(gateway, args.compartment_id, registry, previous=previous)
                else:
                    fresh = collect_inventory(gateway, args.compartment_id, registry, previous=plan, state=state)
                fresh = preserve_report_members(plan, fresh, state)
                state = reconcile_state(fresh, state)
                if not args.exhaustive_discovery:
                    state = reconcile_inventory_state(fresh, state)
                _progress(f'Saving discovery report: {len(fresh.nodes)} resources, {len(fresh.probes)} coverage probes')
                # Save the initial journal before any bulk reconciliation reads.
                workspace.save_plan(fresh)
                workspace.save_state(state)
                if args.exhaustive_discovery:
                    reconcile_report(fresh, state, workspace, gateway, registry)
                text = render_report(fresh, state)
                workspace.save_report(text)
                print(_terminal_report(fresh, state, args.verbose), end='')
                result = 0 if fresh.probes and all(p.status == 'complete' for p in fresh.probes) else 2
            else:
                validate_scope(plan, args.compartment_id)
                tenancy, home, regions, _ = discover_scope(gateway, args.compartment_id)
                if tenancy != plan.tenancy_id or home != plan.home_region:
                    raise CleanupError('Authenticated tenancy or home region differs from saved plan')
                parent = plan.nodes.get(plan.parent_id)
                name = gateway.compartment_records.get(plan.parent_id, {}).get('name')
                shown = replace(plan, nodes=dict(plan.nodes))
                if parent and isinstance(name, str) and name:
                    shown.nodes[plan.parent_id] = replace(parent, display_name=name)
                print('Authenticated retained parent: ' + _display(name or (parent.display_name if parent else '')) + ' | ' + _display(plan.parent_id), file=sys.stderr)
                print('Subscribed regions: ' + _display(', '.join(regions)), file=sys.stderr)
                print(_terminal_report(shown, state, args.verbose), end='', file=sys.stderr, flush=True)
                if not confirm_delete_final(plan, stdin=sys.stdin, stderr=sys.stderr):
                    print('Operation cancelled.', file=sys.stderr)
                    return 1
                state = execute_guided(plan, state, workspace, gateway, registry, args.compartment_id,
                                       args.wait_seconds, interaction=TerminalInteraction(), already_locked=True)
                print(workspace.read_report() if args.verbose else _terminal_report(plan, state, False), end='')
                result = cleanup_result(plan, state)[1]
        return result
    except (CleanupError, OSError, ValueError) as error:
        print('Cleanup failed: ' + ''.join(c if c.isprintable() else '?' for c in str(error)), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Cleanup interrupted; preserve the work directory and rerun.', file=sys.stderr)
        return 1
    finally:
        _artifacts(workspace)
