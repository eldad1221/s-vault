import uuid
import os.path
import datetime
import unittest
from quickbe import Log
import svault.vault as vault


class CryptoTestCase(unittest.TestCase):

    def test_save_crypt_key(self):
        key, key_token = vault.generate_crypto_key()
        file_path = vault.VAULT_KEY_PATH.replace(vault.KEY_TOKEN_STR, key_token)
        Log.debug(f'Key: {key}')
        self.assertEqual(True, os.path.isfile(file_path))

    def test_encrypt_and_decrypt(self):
        original_data = 'Hello world'
        key, key_token = vault.generate_crypto_key()
        encrypted_data = vault.encrypt(key_token=key_token, data=original_data)
        Log.debug(f'Encrypted data: {encrypted_data}')
        decrypted_data = vault.decrypt(key_token=key_token, data=encrypted_data)
        Log.debug(f'Decrypted data: {decrypted_data}')

        self.assertEqual(original_data, decrypted_data)

    def test_read_key(self):
        key, key_token = vault.generate_crypto_key()
        file_path = vault.VAULT_KEY_PATH.replace(vault.KEY_TOKEN_STR, key_token)
        self.assertEqual(True, os.path.isfile(file_path))
        self.assertEqual(key.decode(), vault.read_key(key_token=key_token))

    def test_load_all_keys(self):
        key, key_token = vault.generate_crypto_key()
        Log.debug(f'Token: {key_token}, Key: {key}')
        all_keys = vault.load_all_keys()
        Log.debug(f'{all_keys}')
        self.assertEqual(True, key_token in all_keys)

    def test_save_read_and_delete_secret(self):
        vault.load_all_keys()
        original_data = str(datetime.datetime.now())
        secret_path = 'testing/unittests'
        secret_name = f'VALUE_{uuid.uuid4()}'
        vault.save_secret(
            secret_name=secret_name,
            value=original_data,
            secret_path=secret_path,
            comment='Unit testing secret'
        )

        value = vault.read_secret(secret_name=secret_name, secret_path=secret_path)

        self.assertEqual(value, original_data)

        vault.delete_secret(secret_name=secret_name, secret_path=secret_path)

        with self.assertRaises(FileNotFoundError):
            vault.read_secret(secret_name=secret_name, secret_path=secret_path)

    def test_list_secrets(self):
        secret_path = 'testing'
        secrets = vault.list_secret(secret_path=secret_path)
        Log.debug(secrets)
        self.assertIsInstance(secrets, list)

    def test_get_secrets(self):
        vault.load_all_keys()
        secret_path = 'testing'
        secrets = vault.get_secrets(secret_path=secret_path)
        Log.debug(secrets)
        self.assertIsInstance(secrets, dict)

    def test_path_auth(self):
        path = '/testing/unittests'
        test_cases = {
            'admin': True,
            'developer': True,
            'guest': False
        }

        for user, expected_result in test_cases.items():
            is_authorized = vault.is_authorized_to_path(user=user, secret_path=path)
            Log.debug(f'User {user} got {is_authorized}')
            self.assertEqual(expected_result, is_authorized)


if __name__ == '__main__':
    unittest.main()
