import json
from jose import jwt
from auth_flow_session import auth_flow_session
import time

class tokenrequest:

    def __init__(self, grant_type, code, redirect_uri, client_id, client_secret):
        self.grant_type = grant_type
        self.code = code
        self.redirect_uri = redirect_uri
        self.client_id = client_id
        self.client_secret = client_secret


    def get(self):
        self.auth_flow_session = auth_flow_session()
        self.auth_flow_session.load(self.code)
        self.auth_flow_session.create_access_token()

        response = {}
        response['id_token'] = self._generate_jwt()
        response['access_token'] = self.auth_flow_session.access_token
        response['token_type'] = 'Bearer'
        response['expires_in'] = 3600

        return json.dumps(response)

    def _generate_jwt(self):
        timestamp = int(time.time())

        claims = {'iss': 'http://192.168.1.149:5000',
                  'sub': self.auth_flow_session.claims['sub'],
                  'aud': 'moodle-1',
                  'iat': timestamp,
                  'exp': timestamp + 3600,
                  'given_name': self.auth_flow_session.claims['givenName'],
                  'family_name': self.auth_flow_session.claims['sn'],
                  'email': self.auth_flow_session.claims['mail'],
                  'nonce': self.auth_flow_session.nonce}

        token = jwt.encode(claims, 'secret', algorithm='HS256')

        return token

