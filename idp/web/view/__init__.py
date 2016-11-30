from flask import Flask, request, render_template, redirect
from auth_flow_session import auth_flow_session
from tokenrequest import tokenrequest

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
    ses = auth_flow_session()

    if 'scope' in request.args \
            and 'response_type' in request.args \
            and 'client_id' in request.args \
            and 'redirect_uri' in request.args:
        ses.create(request.args['client_id'],
                         request.args['scope'],
                         request.args['response_type'],
                         request.args['redirect_uri'],
                         request.args['state'],
                         nonce=None if 'nonce' not in request.args else request.args['nonce'])

    elif 'scope' in request.headers \
            and 'response_type' in request.headers \
            and 'client_id' in request.headers \
            and 'redirect_uri' in request.headers:
        ses.create(request.headers.get('client_id'),
                         request.headers.get('scope'),
                         request.headers.get('response_type'),
                         request.headers.get('redirect_uri'),
                         request.headers.get('state'),
                         nonce=None if 'nonce' not in request.headers else request.headers.get('nonce'))


    elif 'code' in request.args:
#        ar = authrequest(client_id=request.args['client_id'], code=request.args['code'])
        ses.load(request.args['code'])

    # if not ar.validated_client:
    #     return '<html>Invalid client ID</html>'


    if 'username' not in request.form or 'password' not in request.form:
        return render_template('auth.html', header_string='code=%s' % (ses.code), username_value='', username_error='', password_error='')
    else:
        username = request.form['username']
        password = request.form['password']

        directory_server = ldap3.Server('10.211.55.8')
        directory_connection = ldap3.Connection(directory_server, user='cn=admin,dc=hd,dc=local', password='Password1')
        directory_connection.bind()

        directory_connection.search('uid=%s,cn=users,dc=hd,dc=local' % username, '(objectclass=person)', attributes=ldap3.ALL_ATTRIBUTES)

        is_authenticated = False

        if len(directory_connection.entries) != 1:
            return render_template('auth.html', header_string='code=%s' % (ses.code), username_value=username, username_error='Unrecognised username', password_error='')
        else:
            user_object = directory_connection.entries[0]
            user_connection = ldap3.Connection(directory_server, user=user_object.entry_dn, password=password, auto_bind=True)
            is_authenticated = user_connection.bound

            for attribute in ['givenName', 'sn', 'mail']:
                if attribute in user_object.entry_attributes_as_dict:
                    ses.set_claims({attribute: user_object.entry_attributes_as_dict[attribute][0]})

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
            return render_template('auth.html', header_string='code=%s' % (ses.code), username_value=username, username_error='', password_error='Incorrect password entered, please try again.')

        # ar.set_user(username)
        ses.set_claims({'sub': username})

        response = redirect("%s%scode=%s&state=%s" % (ses.redirect_uri, '&' if '?' in ses.redirect_uri else '?', ses.code, ses.state), code=302)

        for key, val in ses.__dict__.items():
            response.headers.add(key, val)

        response.headers['state'] = state

        ses.save()

        return response




@app.route('/endpoint', methods=['GET', 'POST'])
def endpoint():
    return '{"sub": "Keith"}'

@app.route('/token', methods=['GET', 'POST'])
def token():


    tr = None
    token = ''

    if 'grant_type' in request.form \
            and 'code' in request.form \
            and 'redirect_uri' in request.form \
            and 'client_id' in request.form \
            and 'client_secret' in request.form:

        tr = tokenrequest(request.form['grant_type'],
                          request.form['code'],
                          request.form['redirect_uri'],
                          request.form['client_id'],
                          request.form['client_secret'])

        token = tr.get()

    return token



