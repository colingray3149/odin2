#!/bin/python3
"""Credential-free remote helper; the host broker alone publishes commits."""
import json
import os
import pathlib
import re
import resource
import subprocess
import sys
import time
import uuid

QUEUE = pathlib.Path('/workspace/.odin-claude/publish')
LIMIT = 32 * 1024 * 1024


def atomic(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('x') as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def git(*args):
    return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', *args], timeout=60).decode().strip()


def bounded_bundle():
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))


def exchange(config, kind, source=None):
    QUEUE.mkdir(mode=0o700, parents=True, exist_ok=True)
    nonce = uuid.uuid4().hex
    request = dict(config, nonce=nonce, kind=kind)
    bundle = QUEUE / (nonce + '.bundle')
    if kind == 'push':
        full = 'refs/heads/' + config['branch']
        # Only the assigned local branch can be published; no revision expressions.
        if source != full:
            raise ValueError('only the assigned local branch may be pushed')
        request['tip'] = git('rev-parse', '--verify', full + '^{commit}')
        subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', 'bundle', 'create', str(bundle), full],
                       check=True, timeout=60, preexec_fn=bounded_bundle)
        if bundle.stat().st_size > LIMIT:
            raise ValueError('bundle exceeds publication limit')
        with bundle.open('rb') as stream:
            os.fsync(stream.fileno())
    atomic(QUEUE / (nonce + '.request'), request)
    ack = QUEUE / (nonce + '.ack')
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            with ack.open() as stream:
                response = json.load(stream)
            if response.get('nonce') != nonce:
                raise ValueError('invalid broker acknowledgment')
            for path in (QUEUE / (nonce + '.request'), bundle, ack):
                path.unlink(missing_ok=True)
            if not response.get('ok'):
                raise ValueError(response.get('error', 'publication rejected'))
            return response
        except FileNotFoundError:
            time.sleep(0.2)
    raise TimeoutError('publication broker did not acknowledge request')


def main():
    with open('/run/odin-material/publication.json') as stream:
        config = json.load(stream)
    if set(config) != {'session', 'branch'} or not re.fullmatch(r'claude/[A-Za-z0-9_-]{1,80}', config['branch']):
        raise ValueError('invalid immutable publication configuration')
    if len(sys.argv) != 3 or sys.argv[2] not in ('', 'odin:'):
        raise ValueError('arbitrary remote URLs are forbidden')
    full = 'refs/heads/' + config['branch']
    pending = []
    for raw in sys.stdin:
        command = raw.rstrip('\n')
        if command == 'capabilities':
            print('push\n\n', end='', flush=True)
        elif command in ('list', 'list for-push'):
            tip = exchange(config, 'list').get('tip')
            if tip:
                print(tip + ' ' + full)
            print('', flush=True)
        elif command.startswith('push '):
            if len(pending) >= 2:
                raise ValueError('multiple push commands are forbidden')
            pending.append(command[5:])
        elif command == '' and pending:
            if len(pending) != 1 or pending[0] != full + ':' + full:
                print('error ' + full + ' only a non-force assigned branch push is permitted')
            else:
                try:
                    exchange(config, 'push', full)
                    print('ok ' + full)
                except Exception:
                    print('error ' + full + ' publication broker rejected push')
            pending.clear()
            print('', flush=True)
        elif command == '':
            break
        else:
            raise ValueError('unsupported remote-helper command')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('odin publication: ' + str(error), file=sys.stderr)
        sys.exit(1)
