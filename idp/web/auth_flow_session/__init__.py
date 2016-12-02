from storage import storage
import json
import uuid

class auth_flow_session:
    def create(self,
                 client_id,
                 scope=None,
                 response_type=None,
                 redirect_uri=None,
                 state=None,
                 nonce=None):
        self.client_id = client_id
        self.scope = scope
        self.response_type = response_type
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.state = state
        self.nonce = nonce

        self.claims = {}
        self.code = uuid.uuid4().hex

        self._persist()

    def load(self, code):
        self.code = code
        self._retrieve()

    def set_claims(self, claims={}):
        for key, value in claims.items():
            self.claims[key] = value

    def create_access_token(self):
        self.access_token = uuid.uuid4().hex

    def save(self):
        self._persist()

    def _persist(self):
        storage.set('sessions_%s' % self.code, json.dumps(self.__dict__))
        storage.expire('sessions_%s' % self.code, 3600) # 1 hour

    def _retrieve(self):
        state = json.loads(storage.get('sessions_%s' % self.code))

        for key, value in state.items():
            self.__dict__[key] = value

