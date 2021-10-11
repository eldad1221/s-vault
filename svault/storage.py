import datetime
from git import Repo
from os import getenv
from quickbe import Log
from pathlib import Path

DEFAULT_SECRET_VAULT = 'default_vault'
DEFAULT_KEYS_STORE = 'default_keys_store'
QUICKBE_VAULT_REMOTE_URL = getenv('QUICKBE_VAULT_REMOTE_URL')
QUICKBE_KEYS_STORE_REMOTE_URL = getenv('QUICKBE_KEYS_STORE_REMOTE_URL')
QUICKBE_VAULT_HOME_FOLDER = getenv('QUICKBE_VAULT_HOME_FOLDER', f'{Path.home()}/vault')
QUICKBE_VAULT_REPOSITORIES_FOLDER = getenv('QUICKBE_VAULT_REPOSITORIES_FOLDER', f'{QUICKBE_VAULT_HOME_FOLDER}/repos')

QUICKBE_VAULT_KEYS_FOLDER = getenv(
    'QUICKBE_VAULT_KEYS_FOLDER',
    f'{QUICKBE_VAULT_REPOSITORIES_FOLDER}/{DEFAULT_KEYS_STORE}'
)
QUICKBE_VAULT_REMOTE_NAME = getenv('QUICKBE_VAULT_REMOTE_NAME', 'origin')


def get_repo(name: str = None) -> Repo:
    if name is None:
        name = DEFAULT_SECRET_VAULT

    repo_path = f'{QUICKBE_VAULT_REPOSITORIES_FOLDER}/{name}'
    if not Path(repo_path).is_dir():
        Repo.init(path=repo_path)

    repo = Repo(path=repo_path)
    return repo


def get_repo_path(repo) -> str:
    return repo.git.working_dir


def commit_repo(user_name: str, name: str = None, files_to_commit: list = None, files_to_remove: list = None):
    repo = get_repo(name=name)
    if files_to_commit is None:
        files_to_commit = repo.untracked_files
    else:
        files_to_commit.extend(repo.untracked_files)
    repo.index.add(items=files_to_commit)
    if files_to_remove is not None:
        repo.index.remove(items=files_to_remove)
        files_to_commit.extend(files_to_remove)
    msg = f'By: {user_name} at {datetime.datetime.now()}, Files affected: {files_to_commit}'
    repo.index.commit(message=msg)
    return msg


def sync_repo(name: str = None):
    repo = get_repo(name=name)
    origin = repo.remote(name=QUICKBE_VAULT_REMOTE_NAME)

    try:
        items = origin.pull()
        for idx, item in enumerate(items):
            Log.debug(f'Item puled {idx}: {item}')
    except Exception:
        Log.error(f'Failed to pulling repository {repo}/{origin}')

    try:
        items = origin.push()
        for idx, item in enumerate(items):
            Log.debug(f'Item pushed {idx}: {item}')
    except Exception:
        Log.error(f'Failed to pushing repository {repo}/{origin}')


def set_repo_remote(url: str, name: str = None):
    repo = get_repo(name=name)
    try:
        origin = repo.remote(name=QUICKBE_VAULT_REMOTE_NAME)
    except ValueError:
        origin = repo.create_remote(name=QUICKBE_VAULT_REMOTE_NAME, url=url)
    Log.info(f'Vault repo {origin.name}: {origin.url}')
