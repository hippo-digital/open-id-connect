import base64
import json
from jose import jwt
from storage import storage

class tokenrequest:

    def __init__(self, grant_type, code, redirect, client_id):
        self.grant_type = grant_type
        self.code = code
        self.client_id = client_id

        self._get_session_state()

    def get(self):
        import random
        access_token = str(random.randint(0, 999999999))

        response = {}
        response['id_token'] = self._generate_jwt()
        response['access_token'] = access_token
        response['token_type'] = 'Bearer'
        response['expires_in'] = 3600

        return json.dumps(response)

    def _generate_jwt(self):
        import time
        timestamp = int(time.time())

        claims = {'iss': 'http://192.168.1.149:5000',
                  'sub': self.session_state['username'],
                  'aud': 'moodle-1',
                  'iat': timestamp,
                  'exp': timestamp + 3600,
                  'given_name': self.session_state['given_name'],
                  'family_name': self.session_state['family_name'],
                  'email': self.session_state['email'],
                  'nonce': self.session_state['nonce']}

        token = jwt.encode(claims, 'secret', algorithm='HS256')

        return token


    def _get_session_state(self):
        self.session_state = json.loads(storage.hget('sessions', '%s.%s' % (self.client_id, self.code)))
