import ldap3

class ldap_authenticator:
    def __init__(self, server, port, user_bind_path):
        self.user_bind_path = user_bind_path

        self.directory_server = ldap3.Server(server)


    def verify_user(self, username, password):
        conn = ldap3.Connection(self.directory_server, user=self.user_bind_path % username, password=password)

        conn.bind()
        if not conn.bound:
            return {'success': False, 'status': 'Failed to bind to directory server', 'message': conn.result['description']}

        conn.search(self.user_bind_path % username, '(objectclass=person)', attributes=ldap3.ALL_ATTRIBUTES)

        if len(conn.entries) == 1:
            ret = {'success': True, 'claims': {}}
            user_object = conn.entries[0]

            for key, value in user_object.entry_attributes_as_dict.items():
                for attribute in ['givenName', 'sn', 'mail']:
                    if attribute in user_object.entry_attributes_as_dict:
                        ret['claims'][attribute] = user_object.entry_attributes_as_dict[attribute][0]

            conn.unbind()
            return ret

        else:
            conn.unbind()
            return {'success': False, 'status': 'Invalid number of search results returned.', 'message': ''}

