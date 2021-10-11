import os
import uuid
import datetime
import unittest
from quickbe import Log
from os.path import join
import svault.storage as storage

REMOTE_REPO_URL = os.getenv('REMOTE_REPO_URL')


class GitTestCase(unittest.TestCase):

    def test_work_with_repo(self):
        repo = storage.get_repo()
        repo_path = storage.get_repo_path(repo=repo)
        Log.debug(repo_path)
        self.assertIn(storage.DEFAULT_SECRET_VAULT, repo_path)

    def test_add_and_commit(self):
        repo = storage.get_repo()
        repo_path = storage.get_repo_path(repo=repo)
        Log.info(repo_path)

        file_name = f'New_file_{uuid.uuid4()}.txt'
        file = open(file=join(repo_path, file_name), mode='w')
        file.write('Delete me.')
        file.close()

        files_to_add = repo.untracked_files
        Log.info(f'Files to add: {files_to_add}')
        msg = storage.commit_repo(user_name='unittest')
        Log.info(f'Commit message: {msg}')

        self.assertGreater(len(files_to_add), 0)
        for file in files_to_add:
            self.assertIn(file, msg)

    def test_change_and_commit(self):
        repo = storage.get_repo()
        repo_path = storage.get_repo_path(repo=repo)
        Log.info(repo_path)

        file_name = f'test_file.txt'
        file = open(file=join(repo_path, file_name), mode='w')
        file.write(f'Changed on {datetime.datetime.now()}')
        file.close()

        files_to_commit = [file_name]
        Log.info(f'Files to commit: {files_to_commit}')
        repo.index.add(items=files_to_commit)
        repo.index.commit(message=f'Unittest {datetime.datetime.now()}')
        self.assertGreater(len(files_to_commit), 0)

    def test_just_commit(self):
        msg = storage.commit_repo(user_name='unittest-user')
        Log.debug(msg)
        self.assertIsInstance(msg, str)

    def test_sync_repo(self):
        storage.sync_repo()
        self.assertEqual(True, True)

    def test_push(self):
        name = 'origin'

        repo = storage.get_repo()

        try:
            origin = repo.remote(name=name)
        except ValueError:
            origin = repo.create_remote(name=name, url=REMOTE_REPO_URL)
        origin.pull()
        origin.push()
        self.assertEqual(True, True)


if __name__ == '__main__':
    unittest.main()
