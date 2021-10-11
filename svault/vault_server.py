import json
import svault.vault as vault
import svault.storage as storage
from svault.storage import QUICKBE_VAULT_REMOTE_URL, QUICKBE_KEYS_STORE_REMOTE_URL
from quickbe.utils import ScheduledJobs, get_schedule_job
from quickbe import WebServer, endpoint, Log, get_env_var, HttpSession

SECRET_NAME_KEY = 'secret_name'
SECRET_PATH_KEY = 'secret_path'
SECRET_VALUE_KEY = 'value'
SECRET_COMMENT_KEY = 'comment'

VAULT_SERVER_READERS_KEY = 'readers'
VAULT_SERVER_WRITERS_KEY = 'writers'

VAULT_SERVER_USERS = {}
VAULT_SERVER_READERS = []
VAULT_SERVER_WRITERS = []


QUICKBE_VAULT_SERVER_APIKEY_HEADER = get_env_var('QUICKBE_VAULT_SERVER_APIKEY_HEADER', 'x-api-key')
QUICKBE_VAULT_SERVER_USER_HEADER = 'x-quickbe-vault-user'


def check_api_key(session: HttpSession) -> int:
    if QUICKBE_VAULT_SERVER_APIKEY_HEADER in session.request.headers:
        apikey = session.request.headers.get(QUICKBE_VAULT_SERVER_APIKEY_HEADER)
        user_name = VAULT_SERVER_USERS.get(apikey)
        if user_name is not None:
            session.response.headers[QUICKBE_VAULT_SERVER_USER_HEADER] = user_name
            return 200
    session.response.response = 'Unauthorized'
    return 401


def _get_user(session: HttpSession) -> str:
    return session.response.headers[QUICKBE_VAULT_SERVER_USER_HEADER]


def _is_authorized_to_write(session: HttpSession) -> bool:
    is_authorized = _get_user(session=session) in VAULT_SERVER_WRITERS
    if not is_authorized:
        session.response.status = 403
        session.response.response = 'No permission'
    return is_authorized


def _is_authorized_to_path(session: HttpSession, secret_path: str) -> bool:
    if not secret_path.startswith('/'):
        secret_path = f'/{secret_path}'
    is_authorized = vault.is_authorized_to_path(user=_get_user(session=session), secret_path=secret_path)
    if not is_authorized:
        session.response.status = 403
        session.response.response = 'No permission'
    return is_authorized


def load_users():
    repo_path = storage.get_repo_path(storage.get_repo())
    f = open(file=f'{repo_path}/.users', mode='r')
    users_data = json.load(f)
    users = {}

    global VAULT_SERVER_READERS
    if VAULT_SERVER_READERS_KEY in users_data:
        users.update(users_data[VAULT_SERVER_READERS_KEY])
        VAULT_SERVER_READERS = list(users_data[VAULT_SERVER_READERS_KEY].keys())

    if VAULT_SERVER_WRITERS_KEY in users_data:
        users.update(users_data[VAULT_SERVER_WRITERS_KEY])
        global VAULT_SERVER_WRITERS
        VAULT_SERVER_WRITERS = list(users_data[VAULT_SERVER_WRITERS_KEY].keys())
        VAULT_SERVER_READERS.extend(VAULT_SERVER_WRITERS)

    users_directory = {}

    for user, user_data in users.items():
        key_token, encrypted_data = user_data.split('.')
        users_directory[vault.decrypt(key_token=key_token, data=encrypted_data)] = user
    global VAULT_SERVER_USERS
    VAULT_SERVER_USERS = users_directory


@endpoint(path='get', validation={
    SECRET_NAME_KEY: {'required': True, 'type': 'string'},
    SECRET_PATH_KEY: {'required': True, 'type': 'string'},
}
          )
def read_secret(session: HttpSession):
    secret_path = session.get_parameter(SECRET_PATH_KEY)
    if _is_authorized_to_path(session=session, secret_path=secret_path):
        if not _is_authorized_to_path(session=session, secret_path=secret_path):
            session.response.status = 403
        return vault.read_secret(
            secret_name=session.get_parameter(SECRET_NAME_KEY),
            secret_path=secret_path
        )


@endpoint(path='put', validation={
    SECRET_NAME_KEY: {'required': True, 'type': 'string'},
    SECRET_PATH_KEY: {'required': True, 'type': 'string'},
    SECRET_VALUE_KEY: {'required': True, 'type': 'string'},
    SECRET_COMMENT_KEY: {'type': 'string'},
}
          )
def save_secret(session: HttpSession):
    secret_path = session.get_parameter(SECRET_PATH_KEY).lower()
    secret_name = session.get_parameter(SECRET_NAME_KEY).upper()
    secret_file_path = f'{secret_path}/{secret_name}{vault.SECRET_FILE_SUFFIX}'
    if _is_authorized_to_write(session=session) and _is_authorized_to_path(session=session, secret_path=secret_path):
        try:
            vault.save_secret(
                secret_name=secret_name,
                secret_path=secret_path,
                value=session.get_parameter(SECRET_VALUE_KEY),
                comment=session.get_parameter(SECRET_COMMENT_KEY)
            )
            storage.commit_repo(_get_user(session=session), files_to_commit=[secret_file_path])
            return 'DONE'
        except Exception as ex:
            Log.error(f'Error while saving secret: {ex}')
            raise ex


@endpoint(path='del', validation={
    SECRET_NAME_KEY: {'required': True, 'type': 'string'},
    SECRET_PATH_KEY: {'required': True, 'type': 'string'},
}
          )
def delete_secret(session: HttpSession):
    secret_path = session.get_parameter(SECRET_PATH_KEY).lower()
    secret_name = session.get_parameter(SECRET_NAME_KEY).upper()
    secret_file_path = f'{secret_path}/{secret_name}{vault.SECRET_FILE_SUFFIX}'
    if _is_authorized_to_write(session=session) and _is_authorized_to_path(session=session, secret_path=secret_path):
        try:
            storage.commit_repo(_get_user(session=session), files_to_remove=[secret_file_path])
            vault.delete_secret(
                secret_name=secret_name,
                secret_path=secret_path
            )
            return 'DONE'
        except Exception as ex:
            Log.error(f'Error while saving secret: {ex}')
            raise ex


@endpoint(path='list', validation={
    SECRET_PATH_KEY: {'required': True, 'type': 'string'},
}
          )
def list_secrets(session: HttpSession):
    secret_path = session.get_parameter(SECRET_PATH_KEY)
    if _is_authorized_to_path(session=session, secret_path=secret_path):
        return {'secrets': vault.list_secret(secret_path=secret_path)}


@endpoint(validation={
    SECRET_PATH_KEY: {'required': True, 'type': 'string'},
}
          )
def get_secrets(session: HttpSession):
    secret_path = session.get_parameter(SECRET_PATH_KEY)
    if _is_authorized_to_path(session=session, secret_path=secret_path):
        return vault.get_secrets(secret_path=secret_path)


def _sync_thread(name: str = None):
    s_job = get_schedule_job(scd_str='every 1 minutes')
    s_job.do(storage.sync_repo, name)
    t = ScheduledJobs(wait_interval=10)
    t.start()
    return t


def _running_checklist() -> bool:
    repo = storage.get_repo()
    check_list_ok = True

    if len(repo.remotes) == 0:
        Log.error(
            f'Repository {repo} does not has remote, you can define remote through env-var '
            f'{QUICKBE_VAULT_REMOTE_URL=}.'.replace('=None', '')
        )
        check_list_ok = False

    repo = storage.get_repo(name=storage.DEFAULT_KEYS_STORE)
    if len(repo.remotes) == 0:
        Log.error(
            f'Repository {repo} does not has remote, you can define remote through env-var '
            f'{QUICKBE_KEYS_STORE_REMOTE_URL=}.'.replace('=None', '')
        )
        check_list_ok = False

    return check_list_ok


def run_me():
    # TODO Checklist before running
    try:
        storage.set_repo_remote(url=QUICKBE_VAULT_REMOTE_URL)
        storage.sync_repo()

        storage.set_repo_remote(url=QUICKBE_KEYS_STORE_REMOTE_URL, name=storage.DEFAULT_KEYS_STORE)
        storage.sync_repo(name=storage.DEFAULT_KEYS_STORE)

        sync_vault_thread = _sync_thread()
        sync_keys_thread = _sync_thread(name=storage.DEFAULT_KEYS_STORE)

        load_users()
        vault.load_all_keys()
    except Exception as ex:
        Log.error(f'{ex}')
    if _running_checklist():
        WebServer.add_filter(check_api_key)
        sw_id = Log.start_stopwatch('Starting Vault server', print_it=True)
        WebServer.start()

        sync_vault_thread.terminate()
        sync_keys_thread.terminate()
        Log.info(f'Vault server stopped after {Log.stopwatch_seconds(stopwatch_id=sw_id)}')
    else:
        Log.error(f'Can not run server, please check previous errors in log.')
