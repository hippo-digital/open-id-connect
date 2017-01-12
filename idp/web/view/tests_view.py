import unittest
import mock
import view
import json
from storage import storage
import re
import time


class tests_view(unittest.TestCase):
    def setUp(self):
        self.app = view.app.test_client()
        self.session_content_1 = {'code': '0123456789012345',
                                  'redirect_uri': 'http://test.app/redirectpath',
                                  'response_type': 'code',
                                  'scope': 'openid profile email',
                                  'claims': {'sub': 'Test User',
                                             'sn': 'User',
                                             'givenName': 'Test',
                                             'mail': 'testuser@test.org'},
                                  'client_id': 'test1',
                                  'code_valid': True}

        self.authorisation_request_1 = {'client_id': 'test-1',
                                        'redirect_uri': 'http://abc',
                                        'response_type': 'code',
                                        'scope': 'openid',
                                        'state': '0123456'}

        self.authorisation_request_with_sub = {'client_id': 'test-1',
                                               'redirect_uri': 'http://abc',
                                               'response_type': 'code',
                                               'scope': 'openid',
                                               'state': '0123456',
                                               'sub': 'test_user'}

    def test_token_whenCalledWithNoParameters_returns400InvalidRequest(self):
        returned_result = self.app.post('/token')

        self.assertEqual(400, returned_result.status_code)
        body = returned_result.data.decode('utf-8')
        error_dict = json.loads(body)
        self.assertIn('error', error_dict)
        self.assertEqual(error_dict['error'], 'invalid_request')

    def test_token_whenCalledWithInvalidClientId_returns400InvalidClient(self):
        storage.hset('clients', 'test-1', '0123456789')
        storage.set('sessions_0123456789012345', json.dumps(self.session_content_1))

        returned_result = self.app.post('/token',
                                        data={'client_id': 'wibble',
                                              'client_secret': '123',
                                              'code': 'invalid',
                                              'grant_type': 'abc',
                                              'redirect_uri': 'http://test.app/redirectpath'})

        self.assertEqual(400, returned_result.status_code)
        body = returned_result.data.decode('utf-8')
        error_dict = json.loads(body)
        self.assertIn('error', error_dict)
        self.assertEqual(error_dict['error'], 'invalid_client')

    def test_token_whenCalledWithInvalidCode_returns400InvalidGrant(self):
        storage.hset('clients', 'test-1', '0123456789')
        storage.set('sessions_0123456789012345', json.dumps(self.session_content_1))

        returned_result = self.app.post('/token',
                                        data={'client_id': 'moodle-1',
                                              'client_secret': 'ml6)>MzlrQz~-3W',
                                              'code': 'invalid',
                                              'grant_type': 'abc',
                                              'redirect_uri': 'http://test.app/redirectpath'})

        self.assertEqual(400, returned_result.status_code)
        body = returned_result.data.decode('utf-8')
        error_dict = json.loads(body)
        self.assertIn('error', error_dict)
        self.assertEqual(error_dict['error'], 'invalid_grant')

    def test_token_whenCalledWithInvalidGrantType_returns400UnsupportedGrantType(self):
        storage.hset('clients', 'test-1', '0123456789')
        storage.set('sessions_0123456789012345', json.dumps(self.session_content_1))

        returned_result = self.app.post('/token',
                                        data={'client_id': 'test-1',
                                              'client_secret': '0123456789',
                                              'code': '0123456789012345',
                                              'grant_type': 'code',
                                              'redirect_uri': 'http://test.app/redirectpath'})

        self.assertEqual(400, returned_result.status_code)
        body = returned_result.data.decode('utf-8')
        error_dict = json.loads(body)
        self.assertIn('error', error_dict)
        self.assertEqual(error_dict['error'], 'unsupported_grant_type')

    def test_token_whenCalledWithValidCode_returnsValidToken(self):
        storage.hset('clients', 'test-1', '0123456789')
        storage.set('sessions_0123456789012345', json.dumps(self.session_content_1))

        returned_result = self.app.post('/token',
                                        data={'client_id': 'test-1',
                                              'client_secret': '0123456789',
                                              'code': '0123456789012345',
                                              'grant_type': 'authorization_code',
                                              'redirect_uri': 'http://test.app/redirectpath'})

        self.assertEqual(200, returned_result.status_code)

    def test_token_whenCalledWithNonMatchingRedirectURI_returns400InvalidGrant(self):
        storage.hset('clients', 'test-1', '0123456789')
        storage.set('sessions_0123456789012345', json.dumps(self.session_content_1))

        returned_result = self.app.post('/token',
                                        data={'client_id': 'test-1',
                                              'client_secret': '0123456789',
                                              'code': '0123456789012345',
                                              'grant_type': 'authorization_code',
                                              'redirect_uri': 'http://test.app/differentredirectpath'})

        self.assertEqual(400, returned_result.status_code)
        body = returned_result.data.decode('utf-8')
        error_dict = json.loads(body)
        self.assertIn('error', error_dict)
        self.assertEqual(error_dict['error'], 'invalid_grant')

    def test_token_whenCalledWithExpiredCode_returns400InvalidGrant(self):
        storage.hset('clients', 'test-1', '0123456789')
        storage.set('sessions_0123456789012345', json.dumps(self.session_content_1))
        storage.expire('sessions_0123456789012345', 1)

        time.sleep(2)

        returned_result = self.app.post('/token',
                                        data={'client_id': 'test-1',
                                              'client_secret': '0123456789',
                                              'code': '0123456789012345',
                                              'grant_type': 'authorization_code',
                                              'redirect_uri': 'http://test.app/redirectpath'})

        self.assertEqual(400, returned_result.status_code)
        body = returned_result.data.decode('utf-8')
        error_dict = json.loads(body)
        self.assertIn('error', error_dict)
        self.assertEqual(error_dict['error'], 'invalid_grant')

    def test_login_whenCalledWithNoArgs_returns400InvalidRequest(self):
        returned_result = self.app.post('/login')

        self.assertEqual(400, returned_result.status_code)
        body = returned_result.data.decode('utf-8')
        error_dict = json.loads(body)
        self.assertIn('error', error_dict)
        self.assertEqual(error_dict['error'], 'invalid_request')

    def test_login_whenCalledWithUnrecognisedClientId_returns400UnauthorizedClient(self):
        req = self.authorisation_request_1
        req['client_id'] = 'nonsense'

        returned_result = self.app.post('/login', data=req)

        self.assertEqual(400, returned_result.status_code)
        body = returned_result.data.decode('utf-8')
        error_dict = json.loads(body)
        self.assertIn('error', error_dict)
        self.assertEqual(error_dict['error'], 'unauthorized_client')
        self.assertIn('state', error_dict)
        self.assertEqual(error_dict['state'], self.authorisation_request_1['state'])

    def test_login_whenCalledWithInvalidScope_returns400InvalidScope(self):
        storage.hset('clients', 'test-1', '0123456789')
        req = self.authorisation_request_1
        req['scope'] = 'wibble'

        returned_result = self.app.post('/login', data=req)

        self.assertEqual(400, returned_result.status_code)
        body = returned_result.data.decode('utf-8')
        error_dict = json.loads(body)
        self.assertIn('error', error_dict)
        self.assertEqual(error_dict['error'], 'invalid_scope')
        self.assertIn('state', error_dict)
        self.assertEqual(error_dict['state'], self.authorisation_request_1['state'])

    def test_login_whenCalledWithInvalidResponseType_returns400InvalidResponseType(self):
        storage.hset('clients', 'test-1', '0123456789')
        req = self.authorisation_request_1
        req['response_type'] = 'not-code'

        returned_result = self.app.post('/login', data=req)

        self.assertEqual(400, returned_result.status_code)
        body = returned_result.data.decode('utf-8')
        error_dict = json.loads(body)
        self.assertIn('error', error_dict)
        self.assertEqual(error_dict['error'], 'unsupported_response_type')
        self.assertIn('state', error_dict)
        self.assertEqual(error_dict['state'], self.authorisation_request_1['state'])

    def test_login_whenCalledWithAuthzFlowParams_returns200LoginPage(self):
        storage.hset('clients', 'test-1', '0123456789')
        req = self.authorisation_request_1

        returned_result = self.app.post('/login', data=req)

        self.assertEqual(200, returned_result.status_code)
        body = returned_result.data.decode('utf-8')

        self.assertIn('form action="/login?', body)

    def test_login_whenCalledWithNonce_returns200AndPersistsNonce(self):
        storage.hset('clients', 'test-1', '0123456789')
        req = self.authorisation_request_1
        req['nonce'] = 'wibble123'

        returned_result = self.app.post('/login', data=req)

        self.assertEqual(200, returned_result.status_code)
        body = returned_result.data.decode('utf-8')

        code = re.search('(?:code=)(\w*)', body).group(1)

        session_raw = storage.get('sessions_%s' % code)
        session = json.loads(session_raw)

        self.assertIn('nonce', session)
        self.assertEqual(session['nonce'], 'wibble123')

    def test_login_whenCalledWithValidCodeUsernameAndPassword_return302RedirectToClient(self):
        storage.hset('clients', 'test-1', '0123456789')
        storage.set('sessions_0123456789012345', json.dumps(self.session_content_1))

        with mock.patch('ldap_authenticator.ldap_authenticator.verify_user') as mock_verifyuser:
            mock_verifyuser.return_value = {'success': True, 'claims': {'givenName': 'Test', 'sn': 'User',
                                                                        'mail': 'testuser@test.com'}}

            returned_result = self.app.post('/login?code=0123456789012345',
                                            data={'username': 'test', 'password': '123'})

            self.assertEqual(302, returned_result.status_code)

    def test_login_whenCalledWithValidCodeAndInvalidUsernameAndPassword_returns200WithFailureMessage(self):
        storage.hset('clients', 'test-1', '0123456789')
        storage.set('sessions_0123456789012345', json.dumps(self.session_content_1))

        with mock.patch('ldap_authenticator.ldap_authenticator.verify_user') as mock_verifyuser:
            mock_verifyuser.return_value = {'success': False, 'claims': {'givenName': 'Test', 'sn': 'User',
                                                                        'mail': 'testuser@test.com'}}

            returned_result = self.app.post('/login?code=0123456789012345',
                                            data={'username': 'test', 'password': '123'})

            body = returned_result.data.decode('utf-8')

            self.assertEqual(200, returned_result.status_code)
            self.assertIn('Incorrect username and/or password entered, please try again.', body)

    def test_loginAndToken_whenCalledWithValidCodeTwice_returns4xx(self):
        storage.hset('clients', 'test-1', '0123456789')
        storage.set('sessions_0123456789012345', json.dumps(self.session_content_1))

        with mock.patch('ldap_authenticator.ldap_authenticator.verify_user') as mock_verifyuser:
            mock_verifyuser.return_value = {'success': True, 'claims': {'givenName': 'Test', 'sn': 'User',
                                                                        'mail': 'testuser@test.com'}}

            returned_result = self.app.post('/login?code=0123456789012345',
                                            data={'username': 'test', 'password': '123'})

            body = returned_result.data.decode('utf-8')

            self.assertEqual(302, returned_result.status_code)

            returned_result = self.app.post('/token',
                                        data={'client_id': 'test-1',
                                              'client_secret': '0123456789',
                                              'code': '0123456789012345',
                                              'grant_type': 'authorization_code',
                                              'redirect_uri': 'http://test.app/redirectpath'})

            self.assertEqual(200, returned_result.status_code)

            returned_result = self.app.post('/token',
                                        data={'client_id': 'test-1',
                                              'client_secret': '0123456789',
                                              'code': '0123456789012345',
                                              'grant_type': 'authorization_code',
                                              'redirect_uri': 'http://test.app/redirectpath'})

            self.assertEqual(400, returned_result.status_code)
            body = returned_result.data.decode('utf-8')
            error_dict = json.loads(body)
            self.assertIn('error', error_dict)
            self.assertEqual(error_dict['error'], 'invalid_request')

    def test_int_loginAndToken_whenCalledWithValidCode_returnsSuccess(self):
        storage.hset('clients', 'test-1', '0123456789')
        storage.set('sessions_0123456789012345', json.dumps(self.session_content_1))


        returned_result = self.app.post('/login?code=0123456789012345',
                                        data={'username': 'brett', 'password': 'Password1'})

        body = returned_result.data.decode('utf-8')

        self.assertEqual(302, returned_result.status_code)

        returned_result = self.app.post('/token',
                                    data={'client_id': 'test-1',
                                          'client_secret': '0123456789',
                                          'code': '0123456789012345',
                                          'grant_type': 'authorization_code',
                                          'redirect_uri': 'http://test.app/redirectpath'})

        self.assertEqual(200, returned_result.status_code)


    # def test_temp_ldap_bind(self):
    #     from ldap_authenticator import ldap_authenticator
    #     service_bind_dn = 'cn=admin,dc=hd,dc=local'
    #     service_password = 'Password1'
    #     search_base_dn = 'dc=hd,dc=local'
    #
    #     ldap = ldap_authenticator('10.211.55.8', 389, service_bind_dn, service_password, search_base_dn)
    #     res = ldap.verify_user('abc', 'brett', 'Password1')


if __name__ == "__main__":
    unittest.main()

