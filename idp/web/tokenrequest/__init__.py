import json
from jose import jwt
from auth_flow_session import auth_flow_session
import time

class tokenrequest:
    issuer_address = 'http://localhost:5000'

    def __init__(self, grant_type, code, redirect_uri, client_id, client_secret, jwt_expiry_seconds, subject_attribute_name=None):
        self.grant_type = grant_type
        self.code = code
        self.redirect_uri = redirect_uri
        self.client_id = client_id
        self.client_secret = client_secret
        self.jwt_expiry_seconds = jwt_expiry_seconds
        self.subject_attribute_name = subject_attribute_name

    def get(self):
        self.auth_flow_session = auth_flow_session()
        self.auth_flow_session.load(self.code)
        self.auth_flow_session.create_access_token()

        response = {}
        response['id_token'] = self._generate_jwt()
        response['access_token'] = self.auth_flow_session.access_token
        response['token_type'] = 'Bearer'
        response['expires_in'] = self.jwt_expiry_seconds

        if not self._validate_redirect_url():
            raise NonMatchingRedirectException

        if not self.auth_flow_session.code_valid:
            raise InvalidCodeException

        self.auth_flow_session.invalidate_code()

        return json.dumps(response)

    def _generate_jwt(self):
        timestamp = int(time.time())

        claims = {'iss': tokenrequest.issuer_address,
                  'aud': self.client_id,
                  'iat': timestamp,
                  'exp': timestamp + self.jwt_expiry_seconds}

        for key, value in self.auth_flow_session.claims.items():
            claims[key] = self.auth_flow_session.claims[key]

        if self.subject_attribute_name != None:
            if self.subject_attribute_name in self.auth_flow_session.claims:
                claims['sub'] = self.auth_flow_session.claims[self.subject_attribute_name]

        if hasattr(self.auth_flow_session, 'nonce'):
            claims['nonce'] = self.auth_flow_session.nonce

        token = jwt.encode(claims, self.client_secret, algorithm='HS256')

        return token

    def _validate_redirect_url(self):
        return self.redirect_uri == self.auth_flow_session.redirect_uri

class NonMatchingRedirectException(Exception):
    def __init__(self):
        None

class InvalidCodeException(Exception):
    def __init__(self):
        None

