from flask import Flask, request, render_template, redirect
from auth_flow_session import auth_flow_session
from tokenrequest import tokenrequest
from ldap_authenticator import ldap_authenticator
import logging, os
from storage import storage
import yaml

app = Flask(__name__)


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
            and 'redirect_uri' in request.args \
            and 'state' in request.args:
        ses.create(request.args['client_id'],
                         request.args['scope'],
                         request.args['response_type'],
                         request.args['redirect_uri'],
                         request.args['state'],
                         nonce=None if 'nonce' not in request.args else request.args['nonce'])

    elif 'scope' in request.headers \
            and 'response_type' in request.headers \
            and 'client_id' in request.headers \
            and 'redirect_uri' in request.headers \
            and 'state' in request.headers:
        ses.create(request.headers.get('client_id'),
                         request.headers.get('scope'),
                         request.headers.get('response_type'),
                         request.headers.get('redirect_uri'),
                         request.headers.get('state'),
                         nonce=None if 'nonce' not in request.headers else request.headers.get('nonce'))

    elif 'code' in request.args:
        ses.load(request.args['code'])

    if 'username' not in request.form or 'password' not in request.form:
        return render_template('auth.html', header_string='code=%s' % (ses.code), username_value='', username_error='', password_error='')
    else:
        username = request.form['username']
        password = request.form['password']

        auth = ldapauth.verify_user(username, password)

        if not auth['success']:
            return render_template('auth.html', header_string='code=%s' % (ses.code), username_value=username,
                                   username_error='Incorrect username and/or password entered, please try again.', password_error='')

        ses.set_claims({'sub': username})
        ses.set_claims(auth['claims'])

        response = redirect("%s%scode=%s&state=%s" % (ses.redirect_uri, '&' if '?' in ses.redirect_uri else '?', ses.code, ses.state), code=302)

        for key, val in ses.__dict__.items():
            response.headers.add(key, val)

        ses.save()

        return response


@app.route('/endpoint', methods=['GET', 'POST'])
def endpoint():
    return '{"sub": "Keith"}'


@app.route('/token', methods=['GET', 'POST'])
def token():
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


def loadconfig():
    SCRIPTPATH = os.path.dirname(os.path.realpath(__file__))
    with open(SCRIPTPATH + '/../config.yml') as cfgstream:
        config = yaml.load(cfgstream)
        return config



log = logging.getLogger('idp')

config = loadconfig()

redis_port = config['sessionstore']['port']
redis_address = config['sessionstore']['address']
idstore_port = config['idstore']['port']
idstore_address = config['idstore']['address']
idstore_bindpath = config['idstore']['bindpath']

storage(redis_address, redis_port)

ldapauth = ldap_authenticator(idstore_address, idstore_port, idstore_bindpath)

