"""Atomic local journals; every writer holds the same process-scoped lock."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
import tempfile

from .model import CleanupError, Plan, State, plan_from_dict, plan_to_dict, state_from_dict, state_to_dict


def _safe_text(value):
    return ''.join(char if char.isprintable() else '?' for char in str(value))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CleanupError('Duplicate JSON object key')
        result[key] = value
    return result


def _nonfinite(value):
    raise CleanupError('Nonfinite JSON number')


def _regular(path):
    """Check without following links, including hard links to outside files."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise CleanupError('Managed artifact must be a regular file without links')


class Workspace:
    def __init__(self, path: Path):
        self.path = Path(path).absolute()
        self._lock_fd = None
        self._lock_pid = None

    def _directory(self):
        if self.path.is_symlink():
            raise CleanupError('Work directory must not be a symlink')
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self.path.is_dir():
            raise CleanupError('Work directory is not a directory')

    @contextmanager
    def locked(self):
        try:
            import fcntl
        except ImportError as error:
            raise CleanupError('Workspace locking requires macOS or Linux') from error
        if self._lock_fd is not None:
            raise CleanupError('Workspace lock is already held')
        fd = None
        acquired = False
        try:
            self._directory()
            target = self.path / '.lock'
            _regular(target)
            fd = os.open(target, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise CleanupError('Invalid workspace lock file')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
            os.fchmod(fd, 0o600)
            self._lock_fd, self._lock_pid = fd, os.getpid()
            yield self
        except OSError as error:
            raise CleanupError('Workspace operation failed: ' + _safe_text(error)) from error
        finally:
            self._lock_fd, self._lock_pid = None, None
            if fd is not None:
                if acquired:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            # Never unlink the lock: waiters must keep sharing the same inode.

    def _writer(self):
        if self._lock_fd is None or self._lock_pid != os.getpid():
            raise CleanupError('Hold the workspace lock before writing artifacts')
        self._directory()
        current = (self.path / '.lock').lstat()
        held = os.fstat(self._lock_fd)
        if current.st_ino != held.st_ino or current.st_dev != held.st_dev or current.st_nlink != 1:
            raise CleanupError('Workspace lock file changed')

    def _read(self, name):
        try:
            self._directory()
            target = self.path / name
            _regular(target)
            fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'r', encoding='utf-8') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise CleanupError('Invalid managed artifact')
                return json.load(stream, object_pairs_hook=_pairs, parse_constant=_nonfinite)
        except (OSError, ValueError, UnicodeError, RecursionError) as error:
            raise CleanupError('Cannot read ' + name + ': ' + _safe_text(error)) from error

    def load(self, parent_id: str) -> tuple[Plan, State]:
        plan = plan_from_dict(self._read('plan.json'))
        state = state_from_dict(self._read('state.json'))
        if plan.parent_id != parent_id or state.parent_id != plan.parent_id or state.tenancy_id != plan.tenancy_id:
            raise CleanupError('Workspace tenancy or retained parent does not match')
        return plan, state

    def _replace(self, name, text):
        temporary = None
        try:
            self._writer()
            target = self.path / name
            _regular(target)
            with tempfile.NamedTemporaryFile(mode='w', dir=self.path, delete=False, encoding='utf-8') as stream:
                temporary = Path(stream.name)
                os.fchmod(stream.fileno(), 0o600)
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            _regular(target)
            os.replace(temporary, target)
            temporary = None
            directory_fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as error:
            raise CleanupError('Cannot save ' + name + ': ' + _safe_text(error)) from error
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def _scope(self, artifact):
        self._writer()
        for name, parser in [('plan.json', plan_from_dict), ('state.json', state_from_dict)]:
            path = self.path / name
            if path.exists() or path.is_symlink():
                existing = parser(self._read(name))
                if existing.parent_id != artifact.parent_id or existing.tenancy_id != artifact.tenancy_id:
                    raise CleanupError('Saving cannot change workspace tenancy or retained parent')

    def save_plan(self, plan: Plan) -> None:
        self._scope(plan)
        self._replace('plan.json', json.dumps(plan_to_dict(plan), indent=2, sort_keys=True, allow_nan=False) + '\n')

    def save_state(self, state: State) -> None:
        self._scope(state)
        self._replace('state.json', json.dumps(state_to_dict(state), indent=2, sort_keys=True, allow_nan=False) + '\n')

    def save_report(self, text: str) -> None:
        self._replace('report.txt', text)


def reconcile_state(plan: Plan, old: State | None) -> State:
    plan_to_dict(plan)
    state = state_from_dict(state_to_dict(old)) if old is not None else State(plan.schema_version, plan.tenancy_id, plan.parent_id, {})
    if state.tenancy_id != plan.tenancy_id or state.parent_id != plan.parent_id:
        raise CleanupError('Refresh cannot change workspace tenancy or retained parent')
    for key in plan.nodes:
        state.records.setdefault(key, {'status': 'discovered', 'attempts': []})
    return state
