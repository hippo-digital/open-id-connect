from flask import Flask, request, render_template, redirect

import logging, os
from storage import storage
import ldap3
import redis

app = Flask(__name__)


log = logging.getLogger('idp')

state = ''

if 'REDIS_PORT' in os.environ:
    redis_addr = os.environ['REDIS_PORT']
else:
    redis_addr = 'tcp://localhost:6379'

redis_port = redis_addr.split(':')[2]
redis_ip = redis_addr.split('//')[1].split(':')[0]
storage(redis_ip, redis_port)



@app.before_request
def log_request():
    log.info('Method=BeforeRequest URL=%s ClientIP=%s Method=%s Proto=%s UserAgent=%s Arguments=%s Form=%s Data=%s'
             % (request.url,
                request.headers.environ['REMOTE_ADDR'] if 'REMOTE_ADDR' in request.headers.environ else 'NULL',
                request.headers.environ['REQUEST_METHOD'],
                request.headers.environ['SERVER_PROTOCOL'],
                request.headers.environ['HTTP_USER_AGENT'] if 'HTTP_USER_AGENT' in request.headers.environ else 'NULL',
                request.args,
                request.form,
                request.data.decode('utf-8')))


@app.route('/login', methods=['GET', 'POST'])
def login():
    from authrequest import authrequest

    ar = None

    # uri = request.headers.get('redirect_uri')

    if 'scope' in request.args \
            and 'response_type' in request.args \
            and 'client_id' in request.args \
            and 'redirect_uri' in request.args:
        ar = authrequest(request.args['client_id'],
                         request.args['scope'],
                         request.args['response_type'],
                         request.args['redirect_uri'],
                         request.args['state'],
                         nonce=None if 'nonce' not in request.args else request.args['nonce'])

    elif 'scope' in request.headers \
            and 'response_type' in request.headers \
            and 'client_id' in request.headers \
            and 'redirect_uri' in request.headers:
        ar = authrequest(request.headers.get('client_id'),
                         request.headers.get('scope'),
                         request.headers.get('response_type'),
                         request.headers.get('redirect_uri'),
                         request.headers.get('state'),
                         nonce=None if 'nonce' not in request.headers else request.headers.get('nonce'))

    elif 'client_id' in request.args and 'code' in request.args:
        ar = authrequest(client_id=request.args['client_id'], code=request.args['code'])

    if not ar.validated_client:
        return '<html>Invalid client ID</html>'


    if 'username' not in request.form or 'password' not in request.form:
        return render_template('auth.html',
                               header_string='client_id=%s&code=%s' % (
                               ar.client_id, ar.code))
    else:
        username = request.form['username']
        password = request.form['password']

        directory_server = ldap3.Server('192.168.1.154')
        directory_connection = ldap3.Connection(directory_server, user='uid=alewis,cn=users,dc=sdh,dc=local', password='Password4')
        directory_connection.bind()

        directory_connection.search('uid=%s,cn=users,dc=sdh,dc=local' % username, '(objectclass=person)', attributes=ldap3.ALL_ATTRIBUTES)

        is_authenticated = False

        if len(directory_connection.entries) != 1:
            return '<html>Unrecognised user</html>'
        else:
            user_object = directory_connection.entries[0]
            user_connection = ldap3.Connection(directory_server, user=user_object.entry_dn, password=password, auto_bind=True)
            is_authenticated = user_connection.bound
            ar.session_state['given_name'] = user_object.entry_attributes_as_dict['givenName'][0]
            ar.session_state['family_name'] = user_object.entry_attributes_as_dict['sn'][0]
            ar.session_state['email'] = user_object.entry_attributes_as_dict['mail'][0]

            user_connection.unbind()


        directory_connection.unbind()


        # redis auth
        # stored_password_hash = storage.hget('userhashes', username)
        # salt = storage.get('salt')
        #
        # import hashlib
        #
        # expected_password = '%s.%s' % (salt, password)
        # expected_password_hash = hashlib.sha512(expected_password.encode('utf-8')).hexdigest()
        #
        # if stored_password_hash == expected_password_hash:
        #     is_authenticated = True


        if not is_authenticated:
            return '<html>Incorrect password</html>'


        ar.set_user(username)

        response = redirect("%s%scode=%s&state=%s" % (ar.session_state['redirect_uri'], '&' if '?' in ar.session_state['redirect_uri'] else '?', ar.code, ar.session_state['state']), code=302)

        for key, val in ar.__dict__.items():
            response.headers.add(key, val)

        response.headers['state'] = state

        return response


@app.route('/endpoint', methods=['GET', 'POST'])
def endpoint():
    return '{"sub": "Keith"}'

@app.route('/token', methods=['GET', 'POST'])
def token():
    from tokenrequest import tokenrequest

    tr = None
    token = ''

    if 'grant_type' in request.form \
            and 'code' in request.form \
            and 'redirect_uri' in request.form:

        tr = tokenrequest(request.form['grant_type'],
                          request.form['code'],
                          request.form['redirect_uri'],
                          request.form['client_id'])

        token = tr.get()

    # POST /token HTTP/1.1
    # Host: openid.c2id.com
    # Content-Type: application/x-www-form-urlencoded
    # Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
    #
    # grant_type=authorization_code
    #  &code=SplxlOBeZQQYbYS6WxSbIA
    #  &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb

    return token



