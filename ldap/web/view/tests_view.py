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



if __name__ == "__main__":
    unittest.main()

