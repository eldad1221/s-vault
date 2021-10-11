import unittest
from quickbe import Log
import quickbe.vault as vault


class EncryptSomethingTestCase(unittest.TestCase):

    def test_encrypt_some_info(self):
        info = 'aq1sw2de3fr4gt5hy6ju7ki8'
        vault.load_all_keys()
        current_token = vault.QUICKBE_VAULT_ALL_KEYS[vault.CURRENT_KEY_STR]
        Log.info(f'Token and encrypted data:\n{current_token}.{vault.encrypt(key_token=current_token, data=info)}')
        self.assertEqual(True, True)


if __name__ == '__main__':
    unittest.main()
