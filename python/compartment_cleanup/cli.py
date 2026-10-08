"""Explicit read-only report and guarded deletion commands."""
import argparse
import math
from pathlib import Path
import re
import sys

from .discovery import discover
from .executor import cleanup_result, execute, reconcile_report
from .gateway import build_gateway
from .handlers.base import Registry
from .handlers.core import BlockBootVolumes, ComputeInstances, IAMPolicies
from .handlers.network import Networks, RoutePreparations
from .handlers.storage import Storage
from .handlers.scheduled import ScheduledResources
from .handlers.logging_analytics import LoggingAnalytics
from .handlers.load_balancers import LoadBalancers
from .model import CleanupError
from .reporting import render_report
from .store import Workspace, reconcile_state


PRESERVE = 'These commands create local files. Preserve the entire work directory until cleanup is finished.'


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
        print(f'{name}: {workspace.path / name}')


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
        if not re.fullmatch(r'ocid1\.compartment\.[a-z0-9]+\.[a-z0-9.-]*\.[A-Za-z0-9_-]+', args.compartment_id):
            parser.error('invalid retained compartment OCID')
        if args.delete and args.confirm_parent != args.compartment_id:
            parser.error('--delete requires --confirm-parent exactly matching --compartment-id')
    except SystemExit as error:
        return int(error.code)
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
            gateway = build_gateway(args.auth, str(Path(args.config_file).expanduser()),
                                    args.profile, args.bootstrap_region)
            registry = build_registry()
            if args.report:
                previous = reconcile_report(plan, state, workspace, gateway, registry) if plan is not None else None
                fresh = discover(gateway, args.compartment_id, registry, previous=previous)
                state = reconcile_state(fresh, state)
                # Save the initial journal before any bulk reconciliation reads.
                workspace.save_plan(fresh)
                workspace.save_state(state)
                reconcile_report(fresh, state, workspace, gateway, registry)
                text = render_report(fresh, state)
                workspace.save_report(text)
                print(text, end='')
                result = 0 if fresh.probes and all(p.status == 'complete' for p in fresh.probes) else 2
            else:
                state = execute(plan, state, workspace, gateway, registry, args.compartment_id,
                                args.wait_seconds, already_locked=True)
                print(workspace.read_report(), end='')
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
