import asyncio
import email
import email.policy
import hashlib
import os
import parsedatetime
import pytz
import random
import smtplib
import socket
import subprocess
import sys
import threading
import time

from base64 import urlsafe_b64encode
from contextlib import AsyncExitStack
from datetime import datetime
from email.headerregistry import Address
from flask import Flask, request, render_template, abort, jsonify
from functools import partial
from itertools import chain
from pathlib import Path
from ruamel.yaml import YAML
from tempfile import TemporaryDirectory

random.seed()

app = Flask(__name__)
_yaml = YAML()
commie_dir = Path(__file__).parent
commie_cfg = _yaml.load(commie_dir / 'commie.yaml')
app.config['COMMIE_ROOTS'] = commie_cfg
os.chdir(commie_dir)
pdtcal = parsedatetime.Calendar()

@app.route('/')
def index():
    if any(r.get('testing') for r in app.config['COMMIE_ROOTS'].values()):
        return render_template('html/index.html')
    else:
        abort(403)

@app.route('/submit', methods=['POST'])
def submit():
    # Gather the submission
    root = request.form['root']
    root_cfg = commie_cfg[root]
    if root not in commie_cfg:
        abort(400)
    submission = {}
    submission['email'] = request.form['email']
    email_hash = hashlib.sha256()
    email_hash.update(submission['email'].encode('utf-8'))
    submission['email_hash'] = urlsafe_b64encode(email_hash.digest()).decode('ascii')

    for field_class, field_list in root_cfg['required fields'].items():
        for field in field_list:
            value = request.form.get(field)
            if not value:
                abort(400)
            submission[field] = value

    for field_class, field_list in root_cfg['optional fields'].items():
        for field in field_list:
            submission[field] = request.form.get(field, '')
    # Add auto-generated information
    submission['date'] = datetime.now(pytz.utc)
    submission['id'] = gen_id()

    work_dir = Path(root_cfg['working directory'])

    # Check if the post exists
    if 'git check exists' in root_cfg:
        checkout_dir = work_dir/'read-only-copy'
        git_branch = root_cfg['git branch']
        git_repo = root_cfg['git repo']
        fresh_clone = False
        if not (checkout_dir/'.git').is_dir():
            fresh_clone = True
            git_clone = subprocess.run(['git', 'clone',
                                        git_repo, str(checkout_dir),
                                        '-b', git_branch])
            if git_clone.returncode != 0:
                abort(500)
        else:
            git_co = subprocess.run(['git', '-C', str(checkout_dir),
                                     'checkout', git_branch])
            if git_co.returncode != 0:
                abort(500)

        try:
            next(checkout_dir.glob(root_cfg['git check exists'].format(**submission)))
        except StopIteration:
            if fresh_clone:
                # the file does not exist!
                abort(403)

            git_pull = subprocess.run(['git', '-C', str(checkout_dir),
                                       'pull', '--force'])
            if git_pull.returncode != 0:
                abort(500)

            try:
                next(checkout_dir.glob(root_cfg['git check exists']))
            except StopIteration:
                # the file does not exist!
                abort(403)

    # establish author's rights
    rights_expire, _ = pdtcal.parseDT(root_cfg["author's rights expire"],
                                      submission['date'], pytz.utc)
    secrets = {}
    for right in root_cfg["author's rights"]:
        os.makedirs(work_dir/'rights'/right, exist_ok=True)
        secret = gen_secret()
        with open(work_dir/'rights'/right/secret, 'w') as fp:
            _yaml.dump({'id': submission['id'],
                        'expires': rights_expire.isoformat()},
                       fp)
        secrets[right] = secret
    # start preparing content with full info
    info = {'data': submission,
            'status': [],
            'url_root': request.url_root,
            'secrets': secrets}
    email_needs_verifying = 'verify email' in root_cfg['pipeline']

    # get something to identify the user by the next time!
    if 'session expires' in root_cfg:
        session_expires, _ = pdtcal.parseDT(root_cfg["session expires"],
                                            submission['date'], pytz.utc)
        user_id = '\n'.join([request.remote_addr, str(request.user_agent),
                             request.headers.get('Accept-Language', 'Ø'),
                             submission['email'], submission['author']])
        hasher = hashlib.sha256()
        hasher.update(user_id.encode('utf-8'))
        user_hash = urlsafe_b64encode(hasher.digest()).decode('ascii')
        info['user_id_hash'] = user_hash

        session_file = work_dir/'session'/user_hash
        if session_file.exists():
            with open(session_file, 'r') as session_fp:
                previous_session_expires = datetime.fromisoformat(session_fp.read())
                if previous_session_expires > submission['date']:
                    # we're good!
                    info['status'].append('pre-verified email')
                    email_needs_verifying = False

    # Save with processing status
    os.makedirs(work_dir/'content', exist_ok=True)
    with open(work_dir/'content'/submission['id'], 'w') as fp:
        _yaml.dump(info, fp)

    # queue deletion
    expires, _ = pdtcal.parseDT(root_cfg["expires"],
                                submission['date'], pytz.utc)
    os.makedirs(work_dir/'expires', exist_ok=True)
    with open(work_dir/'expires'/submission['id'], 'w') as fp:
        fp.write(expires.isoformat())

    # move on
    process_further_web(root, submission['id'])

    # Send response
    if request_wants_json():
        return jsonify({'status': 'ok',
                        'email_needs_verifying': email_needs_verifying})
    else:
        return render_template('html/submit.html',
                               email_needs_verifying=email_needs_verifying,
                               root=root,
                               root_cfg=root_cfg,
                               **submission)

@app.route('/verify/<obj_id>')
def verify(obj_id):
    try:
        root, obj_info = get_by_id(obj_id)
    except ValueError:
        abort(404)

    root_cfg = commie_cfg[root]
    work_dir = Path(root_cfg['working directory'])

    if 'user_id_hash' in obj_info and 'session expires' in root_cfg:
        session_expires, _ = pdtcal.parseDT(root_cfg["session expires"],
                                            obj_info['data']['date'], pytz.utc)
        os.makedirs(work_dir/'session', exist_ok=True)
        session_file = work_dir/'session'/obj_info['user_id_hash']
        with open(session_file, 'w') as fp:
            fp.write(session_expires.isoformat())

    if 'verify email' not in obj_info['status']:
        obj_info['status'].append('verify email')

        with open(work_dir/'content'/obj_id, 'w') as fp:
            _yaml.dump(obj_info, fp)

        process_further_web(root, obj_id)

    return render_template('html/verify.html', root=root,
                           root_cfg=root_cfg)

@app.route('/edit/<secret>', methods=['GET', 'POST'])
def edit(secret):
    for root, root_cfg in commie_cfg.items():
        work_dir = Path(root_cfg['working directory'])
        secret_file = work_dir/'rights'/'edit'/secret
        if secret_file.exists():
            break
    else:
        abort(404)

    with open(secret_file) as fp:
        secret_info = _yaml.load(fp)

    expires = datetime.fromisoformat(secret_info['expires'])
    if expires < datetime.now(pytz.utc):
        abort(403)

    obj_id = secret_info['id']
    with open(work_dir/'content'/obj_id) as fp:
        obj_info = _yaml.load(fp)

    status_message = ''

    if request.method == 'POST':
        changed = False
        just_verified = False

        class FieldMissingError(Exception):
            pass

        try:

            # If the submission had not been verified, consider it verified now.
            # The edit link is only distributed via email in the first place.
            if ('verify email' in root_cfg['pipeline']
                    and 'verify email' not in obj_info['status']):
                obj_info['status'].append('verify email')
                just_verified = True

            for field_class, field_list in commie_cfg[root]['required fields'].items():
                if field_class != 'hidden':
                    for field in field_list:
                        if field in request.form:
                            if obj_info['data'][field] != request.form[field]:
                                changed = True
                                obj_info['data'][field] = request.form[field]
                        else:
                            raise FieldMissingError(field)
            for field_class, field_list in commie_cfg[root]['optional fields'].items():
                if field_class != 'hidden':
                    for field in field_list:
                        if field in request.form:
                            if obj_info['data'][field] != request.form[field]:
                                changed = True
                                obj_info['data'][field] = request.form[field]
                        elif field in obj_info['data']:
                            changed = True
                            del obj_info['data'][field]

            if changed:
                status_message = 'Edit ok'
            else:
                status_message = 'Nothing changed'

            if changed or just_verified:
                with open(work_dir/'content'/obj_id, 'w') as fp:
                    _yaml.dump(obj_info, fp)

            if just_verified:
                process_further_web(root, obj_id)
                status_message += '<br>Email verified'
            elif changed:
                process_further_web(root, obj_id, 'edit')

        except FieldMissingError as e:
            status_message = f'ERROR: {str(e)} is required!'

    return render_template('html/edit.html', root=root, root_cfg=root_cfg,
                           submission=obj_info['data'],
                           status_message=status_message)

@app.route('/delete/<secret>', methods=['GET', 'POST'])
def delete(secret):
    for root, root_cfg in commie_cfg.items():
        work_dir = Path(root_cfg['working directory'])
        secret_file = work_dir/'rights'/'delete'/secret
        if secret_file.exists():
            break
    else:
        abort(404)

    with open(secret_file) as fp:
        secret_info = _yaml.load(fp)

    expires = datetime.fromisoformat(secret_info['expires'])
    if expires < datetime.now(pytz.utc):
        abort(403)

    obj_id = secret_info['id']
    with open(work_dir/'content'/obj_id) as fp:
        obj_info = _yaml.load(fp)

    delete_message = ''

    if request.method == 'POST':
        if 'really-delete' in request.form:
            process_further_web(root, obj_id, 'delete')
            delete_message = 'Deleted!'

    return render_template('html/delete.html', root=root, root_cfg=root_cfg,
                           submission=obj_info['data'],
                           delete_message=delete_message)

@app.route('/ping')
def ping():
    for root in commie_cfg:
        process_further_web(root, '', 'ping')
    return 'pong\n', 200, {'Content-Type': 'text/plain'}

def request_wants_json():
    best = request.accept_mimetypes.best_match(['application/json', 'text/html'])
    return (best == 'application/json' and
            request.accept_mimetypes[best] > request.accept_mimetypes['text/html'])

def get_by_id(obj_id):
    for root, root_cfg in commie_cfg.items():
        work_dir = Path(root_cfg['working directory'])
        if (work_dir/'content'/obj_id).exists():
            break
    else:
        raise ValueError

    with open(work_dir/'content'/obj_id) as fp:
        obj_info = _yaml.load(fp)

    return root, obj_info

def gen_id():
    """
    generate a random ID for a submission
    """
    return urlsafe_b64encode(bytes([random.getrandbits(8) for _ in range(6)])).decode('ascii')

def gen_secret():
    """
    generate a random secret for deleting or editing
    """
    return urlsafe_b64encode(bytes([random.getrandbits(8) for _ in range(18)])).decode('ascii')

def process_further_web(root, obj_id, cmd='process'):
    """
    Make sure the submission is processed.
    """
    work_dir = Path(commie_cfg[root]['working directory'])
    sock_fn = str(work_dir/'worker-socket')
    full_cmd = cmd.encode('ascii') + b' ' + obj_id.encode('ascii') + b'\n'
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(0.1)
    try:
        sock.connect(sock_fn)
    except OSError:
        # The worker process is not responding. It's probably not running.
        # Let's start it!
        python_exe = sys.executable
        if 'uwsgi' in python_exe:
            # this won't do.
            if 'PYTHON' in os.environ:
                python_exe = os.environ['PYTHON']
        env = {}
        env.update(os.environ)
        env['PYTHONPATH'] = os.path.dirname(__file__)
        env['FLASK_APP'] = 'commie'
        subprocess.Popen([python_exe, '-m', 'flask', 'commie-worker'],
              stdin=subprocess.DEVNULL, env=env)
        timeout = time.time() + 2 # two seconds. That's absurdly generous.
        while True:
            try:
                sock.connect(sock_fn)
            except OSError:
                if time.time() > timeout:
                    abort(500)
            else:
                # Connection made!
                break

    # The socket is ready!
    sock.send(full_cmd)
    resp = sock.recv(32)
    if not ((cmd == 'ping' and resp == b'pong\n') or resp == b'ok\n'):
        abort(500)

@app.cli.command()
def commie_worker():
    asyncio.run(commie_async_loop())

async def commie_async_loop():
    async with AsyncExitStack() as stack:
        servers = []
        async for server in start_commie_servers():
            await stack.enter_async_context(server)
            servers.append(server)

        await asyncio.gather(
            expire_loop(),
            *(server.serve_forever() for server in servers))

async def start_commie_servers():
    for root, root_cfg in commie_cfg.items():
        work_dir = Path(root_cfg['working directory'])
        os.makedirs(work_dir, exist_ok=True)
        sock_fn = work_dir/'worker-socket'

        if sock_fn.exists():
            # If the socket exists, see if we can connect
            try:
                reader, writer = await asyncio.open_unix_connection(sock_fn)
            except OSError:
                pass # everything ok!
            else:
                # Connection established!
                writer.close()
                raise RuntimeError(f"Worker is already running at {sock_fn}")

        server = await asyncio.start_unix_server(partial(handle_work, root), sock_fn)
        yield server

async def handle_work(root, reader, writer):
    raw_cmd = await reader.readline()
    try:
        cmd, *args = raw_cmd.decode('utf-8').strip().split()
    except ValueError:
        writer.write(b'error\n')
    else:
        if cmd == 'ping':
            writer.write(b'pong\n')
        elif cmd == 'process':
            obj_id, = args
            asyncio.create_task(process_item(root, obj_id))
            writer.write(b'ok\n')
        elif cmd == 'edit':
            obj_id, = args
            root_cfg = commie_cfg[root]
            work_dir = Path(root_cfg['working directory'])
            with open(work_dir/'content'/obj_id) as fp:
                obj_info = _yaml.load(fp)

            asyncio.create_task(push_to_git(root, obj_info, 'edit'))
            writer.write(b'ok\n')
        elif cmd == 'delete':
            obj_id, = args
            root_cfg = commie_cfg[root]
            work_dir = Path(root_cfg['working directory'])
            with open(work_dir/'content'/obj_id) as fp:
                obj_info = _yaml.load(fp)

            asyncio.create_task(push_to_git(root, obj_info, 'delete'))
            writer.write(b'ok\n')
        else:
            writer.write(b'error\n')

    try:
        await writer.drain()
    except ConnectionResetError:
        pass
    writer.close()

async def expire_loop():
    while True:
        check_expirations()
        await asyncio.sleep(15*60)

def check_expirations():
    for root, root_cfg in commie_cfg.items():
        work_dir = Path(root_cfg['working directory'])
        expire_dir = work_dir/'expires'
        if expire_dir.is_dir():
            for expire_fn in expire_dir.iterdir():
                obj_id = expire_fn.name
                with open(expire_fn) as fp:
                    expire_date = datetime.fromisoformat(fp.read())
                if expire_date < datetime.now(pytz.utc):
                    delete_full(root, obj_id)

        rights_dir = work_dir/'rights'
        if rights_dir.is_dir():
            for rights_subdir in rights_dir.iterdir():
                if not rights_subdir.is_dir():
                    continue
                for right_file in rights_subdir.iterdir():
                    with open(right_file) as fp:
                        right_info = _yaml.load(fp)
                        right_expires = datetime.fromisoformat(right_info['expires'])
                    if right_expires < datetime.now(pytz.utc):
                        os.unlink(right_file)

        session_dir = work_dir/'session'
        if session_dir.is_dir():
            for session_fn in session_dir.iterdir():
                with open(session_fn) as fp:
                    expire_date = datetime.fromisoformat(fp.read())
                if expire_date < datetime.now(pytz.utc):
                    os.unlink(session_fn)

async def process_item(root, obj_id, obj_info=None):
    # Get the current status
    root_cfg = commie_cfg[root]
    work_dir = Path(root_cfg['working directory'])
    if obj_info is None:
        with open(work_dir/'content'/obj_id) as fp:
            obj_info = _yaml.load(fp)

    for task in root_cfg['pipeline']:
        if task in obj_info['status']:
            # this has been done.
            continue
        # This is the first task that has not been done.
        break
    else:
        return

    # task is still in scope
    if task == 'verify email':
        await verification_email(root, obj_info)
    elif task == 'push to git':
        while True:
            try:
                await push_to_git(root, obj_info)
            except RuntimeError:
                # This can actually fail in case of a conflict.
                # try again after some seconds.
                await asyncio.sleep(10 + random.random() * 30)
            else:
                break
    elif task == 'notify admin':
        await notify_admin(root, obj_info)

async def verification_email(root, obj_info):
    root_cfg = commie_cfg[root]
    work_dir = Path(root_cfg['working directory'])

    submission = obj_info['data']
    user_email = submission['email']
    user_address = Address(submission['author'], addr_spec=user_email)
    url_root = obj_info['url_root'].strip('/')

    ctx = {
        'root': root,
        'verification_url': url_root+'/verify/'+submission['id'],
        'author': submission['author'],
        'author_rights': {}
    }

    # establish the author's rights
    rights_expire = None
    for right in root_cfg["author's rights"]:
        secret = obj_info['secrets'][right]
        if rights_expire is None:
            with open(work_dir/'rights'/right/secret, 'r') as fp:
                right_info = _yaml.load(fp)
                rights_expire = datetime.fromisoformat(right_info['expires'])
        ctx['author_rights'][right] = '/'.join([url_root, right, secret])

    tz = pytz.timezone(root_cfg['timezone'])
    ctx['rights_expire'] = rights_expire.astimezone(tz).strftime('%Y-%m-%d %H:%M %Z')

    # Figure out which bits of the submission to echo back
    visible_data = {}
    for field_class, field_list in chain(commie_cfg[root]['required fields'].items(),
                                         commie_cfg[root]['optional fields'].items()):
        if field_class != 'hidden':
            for field in field_list:
                value = submission.get(field)
                if value:
                    visible_data[field] = value

    ctx['visible_data'] = visible_data
    ctx['pre_verified'] = 'pre-verified email' in obj_info['status']

    # build up the verification email
    raw_email = render_template('mail/verification.eml', **ctx).encode('utf-8')
    msg = email.message_from_bytes(raw_email, policy=email.policy.default)
    msg['From'] = str(Address(root, addr_spec=root_cfg['from email']))
    msg['To'] = str(user_address)

    await async_send_mail(root_cfg, msg)

    if ctx['pre_verified']:
        obj_id = obj_info['data']['id']
        obj_info['status'].append('verify email')

        with open(work_dir/'content'/obj_id, 'w') as fp:
            _yaml.dump(obj_info, fp)

        # continue
        await process_item(root, obj_id, obj_info)

async def notify_admin(root, obj_info, change_type='create'):
    root_cfg = commie_cfg[root]
    work_dir = Path(root_cfg['working directory'])

    submission = obj_info['data']
    obj_id = submission['id']
    url_root = obj_info['url_root'].strip('/')

    if change_type == 'create':
        # Give admin the power to delete!
        del_secret = gen_secret()
        with open(work_dir/'expires'/obj_id, 'r') as fp:
            expires = fp.read()
        with open(work_dir/'rights'/'delete'/del_secret, 'w') as fp:
            _yaml.dump({'id': obj_id,
                        'expires': expires},
                       fp)
        obj_info['secrets']['admin-delete'] = del_secret
    else:
        del_secret = obj_info['secrets']['admin-delete']

    tz = pytz.timezone(root_cfg['timezone'])
    ctx = {
        'root': root,
        'author': submission['author'],
        'submission': submission,
        'date': submission['date'].astimezone(tz).strftime('%Y-%m-%d %H:%M %Z'),
        'delete_url': '/'.join([url_root, 'delete', del_secret]),
        'change_type': change_type
    }

    # build up the verification email
    raw_email = render_template('mail/admin_notification.eml', **ctx).encode('utf-8')
    msg = email.message_from_bytes(raw_email, policy=email.policy.default)
    msg['From'] = str(Address(root, addr_spec=root_cfg['from email']))
    msg['To'] = root_cfg['admin email']

    await async_send_mail(root_cfg, msg)

    if change_type == 'create':
        # everything ok? Great.
        obj_info['status'].append('notify admin')

        with open(work_dir/'content'/obj_id, 'w') as fp:
            _yaml.dump(obj_info, fp)

        # continue
        await process_item(root, obj_id, obj_info)


async def async_send_mail(root_cfg, msg):
    loop = asyncio.get_running_loop()
    fut = loop.create_future()

    def actually_send():
        # send the message!
        # This should be async, but that's not for the here and now
        try:
            with smtplib.SMTP(root_cfg['smtp server']) as smtp:
                if 'smtp user' in root_cfg:
                    smtp.login(root_cfg['smtp user'], root_cfg['smtp password'])

                smtp.send_message(msg)
        except BaseException as e:
            loop.call_soon_threadsafe(fut.set_exception, e)
        else:
            loop.call_soon_threadsafe(fut.set_result, None)

    th = threading.Thread(target=actually_send)
    th.start()
    await fut

async def push_to_git(root, obj_info, change_type='create'):
    obj_id = obj_info['data']['id']
    # First, we need the git repository
    root_cfg = commie_cfg[root]
    work_dir = Path(root_cfg['working directory'])
    git_repo = root_cfg['git repo']
    git_branch = root_cfg['git branch']

    with TemporaryDirectory(dir=work_dir) as git_work_dir:
        # run: git clone $git_repo $git_work_dir -b $git_branch
        git_clone = await asyncio.create_subprocess_exec(
            'git', 'clone', str(git_repo), git_work_dir, '-b', git_branch)
        await git_clone.wait()
        if git_clone.returncode != 0:
            raise RuntimeError

        # We now have an up-to-date copy of the repository
        target_fn_rel = root_cfg['git target location'].format(**obj_info['data'])
        target_fn_abs = os.path.join(git_work_dir, target_fn_rel)
        target_dir = os.path.dirname(target_fn_abs)
        os.makedirs(target_dir, exist_ok=True)

        if change_type == 'delete':
            git_rm = await asyncio.create_subprocess_exec(
                'git', '-C', git_work_dir, 'rm', str(target_fn_rel))
            await git_rm.wait()
            if git_rm.returncode != 0:
                raise RuntimeError
        else:
            with open(target_fn_abs, 'w') as fp:
                fp.write(render_template('output.md', **obj_info['data']))

            # Now tell git about it!
            git_add = await asyncio.create_subprocess_exec(
                'git', '-C', git_work_dir, 'add', str(target_fn_rel))
            await git_add.wait()
            if git_add.returncode != 0:
                raise RuntimeError

        if change_type == 'edit':
            commit_msg = 'Comment edited by '+obj_info['data']['author']
        elif change_type == 'delete':
            commit_msg = 'Comment deleted by '+obj_info['data']['author']
        else:
            commit_msg = 'New comment from '+obj_info['data']['author']

        git_ci = await asyncio.create_subprocess_exec(
            'git', '-C', git_work_dir, 'commit',
            f'--author=commie <{root_cfg["from email"]}>',
            '-m', commit_msg,
            '-o', '--', str(target_fn_rel))
        await git_ci.wait()
        if git_ci.returncode != 0:
            raise RuntimeError

        git_push = await asyncio.create_subprocess_exec(
            'git', '-C', git_work_dir, 'push')
        await git_push.wait()
        if git_push.returncode != 0:
            raise RuntimeError

    # everything ok? Great.
    if change_type == 'create':
        obj_info['status'].append('push to git')

        with open(work_dir/'content'/obj_id, 'w') as fp:
            _yaml.dump(obj_info, fp)

        # continue
        await process_item(root, obj_id, obj_info)
    elif change_type == 'edit':
        if 'notify admin' in obj_info['status']:
            await notify_admin(root, obj_info, change_type=change_type)
    elif change_type == 'delete':
        delete_full(root, obj_id, obj_info)
        if 'notify admin' in obj_info['status']:
            await notify_admin(root, obj_info, change_type=change_type)

def delete_full(root, obj_id, obj_info=None):
    root_cfg = commie_cfg[root]
    work_dir = Path(root_cfg['working directory'])

    if obj_info is None:
        with open(work_dir/'content'/obj_id) as fp:
            obj_info = _yaml.load(fp)

    for right, secret in obj_info['secrets'].items():
        if right == 'admin-delete':
            right = 'delete'
        secret_path = work_dir/'rights'/right/secret
        if secret_path.exists():
            os.unlink(secret_path)

    expires_path = work_dir/'expires'/obj_id
    if expires_path.exists():
        os.unlink(expires_path)

    os.unlink(work_dir/'content'/obj_id)
