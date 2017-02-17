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
            ldap = ldap_authenticator.ldap_authenticator('ldap://example.com', None, None, None, None, {'sn': 'family_name', 'givenName': 'given_name', 'mail': 'email', 'employeeNumber': 'id_number'})
            res = ldap.verify_user(0, 'user', 'password')

            self.assertEqual(res['success'], True)
            self.assertEqual(res['claims']['family_name'], 'Smith')
            self.assertEqual(res['claims']['given_name'], 'Sandra')
            self.assertEqual(res['claims']['email'], 'sandra.smith@example.org')
            self.assertEqual(res['claims']['id_number'], '123456')


    def test_verify_user_whenCalledWithInvalidUsernameAndPassword_returnsUserDetails(self):
        # ldap_conn = mock.patch('ldap3.Connection', entries=[''])
        with mock.patch('ldap3.Connection', entries=[user_obj()], bound=False, result={'description': 'Could not bind'}, spec=True) as ldap_conn:
            ldap = ldap_authenticator.ldap_authenticator('ldap://example.com', None, None, None, None, {'sn': 'family_name', 'givenName': 'given_name', 'mail': 'email', 'employeeNumber': 'id_number'})
            res = ldap.verify_user(0, 'user', 'password')

            self.assertEqual(res['success'], False)
            self.assertEqual(res['status'], 'Failed to bind to directory server')




class user_obj:
    def __init__(self):
        self.entry_dn = ''
        self.entry_attributes_as_dict = {'sn': ['Smith'], 'givenName': ['Sandra'], 'mail': ['sandra.smith@example.org'], 'employeeNumber': ['123456']}


if __name__ == "__main__":
    unittest.main()

