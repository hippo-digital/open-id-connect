from storage import storage
import json

class authrequest:
    def __init__(self,
                 client_id,
                 scope=None,
                 response_type=None,
                 redirect_uri=None,
                 state=None,
                 response_mode=None,
                 nonce=None,
                 code=None,
                 display=None,
                 prompt=None,
                 max_age=None,
                 ui_locales=None,
                 id_token_hint=None,
                 login_hint=None,
                 acr_values=None):

        self.session_state = {}

        self.scope = scope
        self.response_type = response_type
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.state = state
        self.nonce = nonce
        self.code = code

        self.validated_client = False
        client_record = storage.hget('clients', self.client_id)

        if client_record != None:
            self.validated_client = True

            if self.code == None:
                import time
                timestamp = int(time.time())

                import random
                self.code = str(random.randint(0, 999999999999))

                self.session_state['state'] = self.state
                self.session_state['exp'] = timestamp + 30
                self.session_state['nonce'] = self.nonce
                self.session_state['redirect_uri'] = self.redirect_uri

                self._set_session_state()
            else:
                self._get_session_state()


    def set_user(self, username):
        self.session_state['username'] = username
        self._set_session_state()


    def _get_session_state(self):
        self.session_state = json.loads(storage.hget('sessions', '%s.%s' % (self.client_id, self.code)))


    def _set_session_state(self):
        storage.hset('sessions', '%s.%s' % (self.client_id, self.code), json.dumps(self.session_state))