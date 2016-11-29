import unittest
import view
import re
import base64

class tests_view(unittest.TestCase):

    def setUp(self):
        self.app = view.app.test_client()

    def test_login_whenCalledWithoutArgs_redirectsToLoginPage(self):
        returned_result = self.app.post('/login')

        self.assertEqual(200, returned_result.status_code)
        self.assertIn('form action="/login"', returned_result.data.decode('utf-8'))

    def test_login_whenCalledWithoutArgs_redirectsToLoginPage(self):
        returned_result = self.app.post('/login?scope=abc&response_type=def&client_id=ghi&redirect_uri=http://app.local/login', data=dict(username='user1', password='password1'))

        self.assertEqual(302, returned_result.status_code)
        # self.assertIn('code', returned_result.request.args)
        # self.assertIn('form action="/login"', returned_result.data.decode('utf-8'))

    def test_token_whenCalled_returnsStuff(self):
        returned_result = self.app.post('/token', data=dict(grant_type='test', code='123456789', redirect_uri='http://abc.def/'), headers={'Authorization': 'Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW'})

        self.assertEqual(1, 2)


    def test_authactivate_whenCalled_returnsValidPreCannedResponse(self):
        reply_regex = '<gpPARAM name=\"reply_url\">http:\/\/(.*)\/login\/authactivate<\/gpPARAM>'

        returned_result = self.app.post('/login/authactivate')

        self.assertEqual(returned_result._status_code, 200)
        content = returned_result.data.decode(returned_result.charset)
        self.assertIn('<?xml version="1.0" encoding="UTF-8"?>', content)
        m = re.search(reply_regex, content)
        self.assertIsNotNone(returned_result)


    def test_authvalidate_whenCalled_returnsValidPreCannedResponse(self):
        returned_result = self.app.post('/login/authvalidate', data='<gpParam name="uid">1234</gpParam>')

        self.assertEqual(returned_result._status_code, 200)
        content = returned_result.data.decode(returned_result.charset)
        self.assertIn('<?xml version="1.0" encoding="UTF-8"?>', content)
        self.assertIsNotNone(returned_result)


    def test_authlogout_whenCalled_returnsValidPreCannedResponse(self):
        returned_result = self.app.post('/login/authlogout', headers={"REMOTE_ADDR":"127.0.0.10"}) #, data='<!DOCTYPE USER SYSTEM "gpOBJECT.DTD"><gpOBJECT><gpPARAM name="auth_method">3</gpPARAM><gpPARAM name="app_url">NHST</gpPARAM><gpPARAM name="log_session_id">NO514OzPww</gpPARAM><gpPARAM name="device_id">79781416,ClientIP=10.0.2.15</gpPARAM><gpPARAM name="service">ACTIVATION</gpPARAM></gpOBJECT>')

        self.assertEqual(returned_result._status_code, 200)
        content = returned_result.data.decode(returned_result.charset)
        self.assertIn('<HTML><STATUS>OK</STATUS></HTML>', content)
        self.assertIsNotNone(returned_result)


    def test_roleselection_whenCalled_returnsValidPreCannedResponse(self):
        returned_result = self.app.get('/saml/RoleSelectionGP.jsp', headers={
            "REMOTE_ADDR": "127.0.0.10"})  # , data='<!DOCTYPE USER SYSTEM "gpOBJECT.DTD"><gpOBJECT><gpPARAM name="auth_method">3</gpPARAM><gpPARAM name="app_url">NHST</gpPARAM><gpPARAM name="log_session_id">NO514OzPww</gpPARAM><gpPARAM name="device_id">79781416,ClientIP=10.0.2.15</gpPARAM><gpPARAM name="service">ACTIVATION</gpPARAM></gpOBJECT>')

        self.assertEqual(returned_result._status_code, 200)
        content = returned_result.data.decode(returned_result.charset)
        self.assertIn('<HTML><STATUS>OK</STATUS></HTML>', content)
        self.assertIsNotNone(returned_result)


if __name__ == "__main__":
    unittest.main()

