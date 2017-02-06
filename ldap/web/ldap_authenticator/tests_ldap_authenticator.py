import unittest
import mock
import view
import json
from storage import storage
import re
import time
import ldap_authenticator


class tests_ldap_authenticator(unittest.TestCase):
    def setUp(self):
        self.wibble = None

    def test_verify_user_whenCalledWithValidUsernameAndPassword_returnsUserDetails(self):
        # ldap_conn = mock.patch('ldap3.Connection', entries=[''])
        with mock.patch('ldap3.Connection', entries=[user_obj()], bound=True, spec=True) as ldap_conn:
            # with mock.patch('ldap3.Connection.entries') as ldap_conn2:
            # ldap_conn.bound = True
            # ldap_conn.entries = 17 # = [{'wibble': '123'}]



            ldap = ldap_authenticator.ldap_authenticator('ldap://example.com', None, None, None, None, {'sn': 'family_name'})
            res = ldap.verify_user(0, 'user', 'password')
            True


class user_obj:
    def __init__(self):
        self.entry_dn = ''
        self.entry_attributes_as_dict = {}


if __name__ == "__main__":
    unittest.main()

