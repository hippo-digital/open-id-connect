import ldap3
import logging

class ldap_authenticator:
    def __init__(self, server, port, service_bind_dn, service_password, search_base_dn):
        self.log = logging.getLogger('idp.ldap')

        self.service_bind_dn = service_bind_dn
        self.service_password = service_password
        self.search_base_dn = search_base_dn

        self.directory_server = ldap3.Server(server)

        self.log.info('LDAP Server=%s Bind Path=%s' % (self.directory_server, self.service_bind_dn))

    def verify_user(self, transaction_id, username, password):
        log_header = 'Method=VerifyUser Transaction=%s' % transaction_id

        self.log.info(log_header + ' Message=Starting LDAP Search Bind Path=%s' % (self.service_bind_dn))
        conn = ldap3.Connection(self.directory_server, self.service_bind_dn, password=self.service_password)

        self.log.info(log_header + ' Username=%s' % username)

        conn.bind()
        if not conn.bound:
            self.log.error(log_header + ' Failed to bind to directory server: %s' % (conn.result['description']))
            return {'success': False, 'status': 'Failed to bind to directory server', 'message': conn.result['description']}

        conn.search(self.search_base_dn, '(&(objectclass=person)(uid=%s))' % username, attributes=ldap3.ALL_ATTRIBUTES)
        self.log.info(log_header + ' Message=LDAP Search Returned Objects Count=%s' % len(conn.entries))

        if len(conn.entries) == 1:
            ret = {'success': True, 'claims': {}}
            user_object = conn.entries[0]

            for key, value in user_object.entry_attributes_as_dict.items():
                for attribute in ['givenName', 'sn', 'mail']:
                    if attribute in user_object.entry_attributes_as_dict:
                        ret['claims'][attribute] = user_object.entry_attributes_as_dict[attribute][0]

            self.log.info(log_header + ' Message=Object retrieved Claims=%s' % ret['claims'])

            conn.unbind()
            return ret

        else:
            conn.unbind()
            self.log.error(log_header + ' Message=Failed to retrieve object, invalid number of results returned Count=%s' % len(conn.entries))
            return {'success': False, 'status': 'Invalid number of search results returned.', 'message': ''}

