import unittest
import view


class tests_view(unittest.TestCase):
    def setUp(self):
        self.app = view.app.test_client()
        self.test_server = {'address': '10.211.55.8',
                            'port': '389',
                            'service_bind_dn': 'cn=admin,dc=hd,dc=local',
                            'service_bind_password': 'Password1'}
        self.claim_attributes = {'sn': 'family_name', 'givenName': 'given_name', 'mail': 'email', 'employeeNumber': 'id_number'}
        self.search_base_dn_list = ['cn=users,dc=hd,dc=local', 'ou=users2,dc=hd,dc=local']

    def test_getuserdetails_whenCalledWithSingleOUAndValidUserAndPasswordInDifferentOU_returnsNotSuccessful(self):
        from ldap_authenticator import ldap_authenticator

        ldap = ldap_authenticator(self.test_server['address'],
                                                     self.test_server['port'],
                                                     self.test_server['service_bind_dn'],
                                                     self.test_server['service_bind_password'],
                                                     [self.search_base_dn_list[1]],
                                                     self.claim_attributes)

        res = ldap.verify_user(0, 'test_user_1', 'Password1')

        self.assertEqual(False, res['success'])

    def test_getuserdetails_whenCalledWithSingleOUAndValidUserAndPassword_returnsUserDetails(self):
        from ldap_authenticator import ldap_authenticator

        ldap = ldap_authenticator(self.test_server['address'],
                                                     self.test_server['port'],
                                                     self.test_server['service_bind_dn'],
                                                     self.test_server['service_bind_password'],
                                                     [self.search_base_dn_list[0]],
                                                     self.claim_attributes)

        res = ldap.verify_user(0, 'test_user_1', 'Password1')

        self.assertEqual(True, res['success'])

    def test_getuserdetails_whenCalledWithMultipleOUAndValidUserAndPassword_returnsUserDetails(self):
        from ldap_authenticator import ldap_authenticator

        ldap = ldap_authenticator(self.test_server['address'],
                                                     self.test_server['port'],
                                                     self.test_server['service_bind_dn'],
                                                     self.test_server['service_bind_password'],
                                                     self.search_base_dn_list,
                                                     self.claim_attributes)

        res = ldap.verify_user(0, 'test_user_0', 'Password1')

        self.assertEqual(True, res['success'])

    def test_getuserdetails_whenCalledWithMultipleOUAndMultipleValidUsersAndPassword_returnsUserDetails(self):
        from ldap_authenticator import ldap_authenticator

        ldap = ldap_authenticator(self.test_server['address'],
                                                     self.test_server['port'],
                                                     self.test_server['service_bind_dn'],
                                                     self.test_server['service_bind_password'],
                                                     self.search_base_dn_list,
                                                     self.claim_attributes)

        for i in range(0, 5):
            res = ldap.verify_user(0, 'test_user_%s' % i, 'Password1')
            self.assertEqual(True, res['success'])



