import unittest
from mock import patch, MagicMock
from mock import MagicMock
from tokenrequest import tokenrequest, SubjectMissingException
from auth_flow_session import auth_flow_session
from jose import jwt
import json

class tests_tokenrequest(unittest.TestCase):
    def setUp(self):
        self.test_claims_1 = {'nonce': '456',
                           'sub': 'test_subject',
                           'employeeNumber': 'empNo'}

        self.test_claims_2 = {'nonce': '456',
                           'sub': 'test_subject'}


    def test_get_whenCalledWithValidAuthSession_returnsValidToken(self): #, afs, afs_load, afs_create_access_token, afs_invalidate_code):
        # MagicMock
        with patch('tokenrequest.auth_flow_session') as afs:
            inst = afs.return_value
            inst.load.return_value = None
            inst.access_token = '123'
            inst.nonce = '456'
            inst.redirect_uri = '3'
            inst.aud = 'client1'
            inst.claims = self.test_claims_1

            tr = tokenrequest('1', '2', '3', 'client1', 'cli.secret', 6)

            token = json.loads(tr.get())
            jw_token = jwt.decode(token['id_token'], 'cli.secret', algorithms='HS256', audience='client1')

            self.assertEqual(jw_token['sub'], 'test_subject')


    def test_get_whenCalledWithValidAuthSessionAndPatchedEmployeeNumber_returnsValidToken(self):
        # MagicMock
        with patch('tokenrequest.auth_flow_session') as afs:
            inst = afs.return_value
            inst.load.return_value = None
            inst.access_token = '123'
            inst.nonce = '456'
            inst.redirect_uri = '3'
            inst.aud = 'client1'
            inst.claims = self.test_claims_1

            tr = tokenrequest('1', '2', '3', 'client1', 'secret', 6, subject_attribute_name='employeeNumber')

            token = json.loads(tr.get())
            jw_token = jwt.decode(token['id_token'], 'secret', algorithms='HS256', audience='client1')

            self.assertEqual(jw_token['sub'], 'empNo')

    def test_get_whenCalledWithValidAuthSessionAndEmployeeNumberAsSubjectButMissing_returnsException(self):
        # MagicMock
        with patch('tokenrequest.auth_flow_session') as afs:
            inst = afs.return_value
            inst.load.return_value = None
            inst.access_token = '123'
            inst.nonce = '456'
            inst.redirect_uri = '3'
            inst.aud = 'client1'
            inst.claims = self.test_claims_2

            tr = tokenrequest('1', '2', '3', 'client1', 'secret', 6, subject_attribute_name='employeeNumber')

            with self.assertRaises(SubjectMissingException):
                token = json.loads(tr.get())

            None
            # jw_token = jwt.decode(token['id_token'], 'secret', algorithms='HS256', audience='client1')
            #
            # self.assertEqual(jw_token['sub'], 'empNo')


if __name__ == "__main__":
    unittest.main()

