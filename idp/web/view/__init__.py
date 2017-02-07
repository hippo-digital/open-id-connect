from flask import Flask, request, render_template, redirect, abort
from auth_flow_session import auth_flow_session
from tokenrequest import tokenrequest, NonMatchingRedirectException, InvalidCodeException
from storage import storage
import logging, os
import yaml
import string
import random
import hashlib
import json
import requests


app = Flask(__name__)


@app.before_request
def log_request():
    transaction_id = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(6)])
    request.environ['transaction_id'] = transaction_id

    log.info('Method=BeforeRequest Transaction=%s RequestMethod=%s URL=%s ClientIP=%s Method=%s Proto=%s UserAgent=%s Arguments=%s Data=%s'
             % (transaction_id,
                request.method,
                request.url,
                request.headers.environ['REMOTE_ADDR'] if 'REMOTE_ADDR' in request.headers.environ else 'NULL',
                request.headers.environ['REQUEST_METHOD'],
                request.headers.environ['SERVER_PROTOCOL'],
                request.headers.environ['HTTP_USER_AGENT'] if 'HTTP_USER_AGENT' in request.headers.environ else 'NULL',
                request.args,
                request.data.decode('utf-8')))

@app.route('/login', methods=['GET', 'POST'])
def login():
    log_header = 'Method=login Transaction=%s' % (request.environ['transaction_id'])
    log.info(log_header + ' Message=Method Called')

    fields = get_all_fields(request)

    log.info(log_header + ' Message=Fields received Fields=%s' % fields)

    ses = auth_flow_session()

    if 'scope' in fields \
            and 'response_type' in fields \
            and 'client_id' in fields \
            and 'redirect_uri' in fields \
            and 'state' in fields:

        if not check_client_auth(fields['client_id']):
            log.info(log_header + ' Message=ClientID not recognised ClientID=%s' % fields['client_id'])
            return json.dumps({'error': 'unauthorized_client', 'state': fields['state']}), 400

        if not check_scope(fields['scope']):
            log.info(log_header + ' Message=Invalid scope provided Scope=%s' % fields['scope'])
            return json.dumps({'error': 'invalid_scope', 'state': fields['state']}), 400

        if not check_response_type(fields['response_type']):
            log.info(log_header + ' Message=Invalid response type ResponseType=%s' % fields['response_type'])
            return json.dumps({'error': 'unsupported_response_type', 'state': fields['state']}), 400

        if not check_state(fields['state']):
            log.info(log_header + ' Message=Invalid state State=%s' % fields['state'])
            return json.dumps({'error': 'invalid_request', 'state': fields['state']}), 400

        ses.create(fields['client_id'],
                   fields['scope'],
                   fields['response_type'],
                   fields['redirect_uri'],
                   state=None if 'state' not in fields else fields['state'],
                   nonce=None if 'nonce' not in fields else fields['nonce'])

        log.info(log_header + ' Message=Created Session Session=%s' % ses.__dict__)

        log.info(log_header + ' Message=Returning authentication form')
        return render_template('auth.html', header_string='code=%s' % (ses.code), username_value='', username_error='', password_error='')

    elif 'code' in fields \
            and 'username' in request.form \
            and 'password' in request.form:

        log.info(log_header + ' Message=Code received, loading session Code=%s' % fields['code'])
        ses.load(fields['code'])
        log.info(log_header + ' Message=Session loaded for code Code=%s Session=%s' % (fields['code'], ses.__dict__))

        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.md5(password.encode('utf-8')).hexdigest()

        log.info(log_header + ' Message=Username and/or password received Username=%s Password=%s' % (
        request.form['username'], hashed_password))

        log.info(log_header + ' Message=Validating username/password against LDAP')

        try:
            ldap_response = requests.post(idservice, data={'username': username, 'password': password})
            log.info(log_header + ' Message=LDAP validation returned HTTPStatus=%s' % ldap_response.status_code)

            if ldap_response.status_code == 200:
                ldap_content = json.loads(ldap_response.text)
                log.info(log_header + ' Message=LDAP validation returned Content=%s' % ldap_content)

                if ldap_content['success']:
                    ses.set_claims({'sub': ldap_content['sub']})
                    ses.set_claims(ldap_content['claims'])


                    response_uri = ses.redirect_uri

                    if hasattr(ses, 'state'):
                        response_uri = '%s%scode=%s&state=%s' % (response_uri, '&' if '?' in ses.redirect_uri else '?', ses.code, ses.state)
                    else:
                        response_uri = '%s%scode=%s' % (response_uri, '&' if '?' in ses.redirect_uri else '?', ses.code)

                    response = redirect(response_uri, code=302)
                    log.info(log_header + ' Message=Response prepared URI=%s' % (response.location))

                    ses.save()

                    return response

                else:
                    log.info(log_header + ' Message=Returning login form with auth failure status')
                    return render_template('auth.html', header_string='code=%s' % (ses.code), username_value=username,
                                               username_error='Incorrect username and/or password entered, please try again.',
                                               password_error='')
            else:
                log.info(log_header + ' Message=LDAP Service Failure')
                return render_template('auth.html', header_string='code=%s' % (ses.code), username_value=username,
                                       username_error='A service failure has occured.  Please contact your systems administrator.',
                                       password_error='')

        except Exception as e:
            log.error("Failed to validate user in ldap", e)
            return abort(500)

    else:
        log.info(log_header + ' Message=Required fields missing Fields=%s' % fields)
        error = {'error': 'invalid_request'}

        if 'state' in fields:
            error['state'] = fields['state']

        return json.dumps(error), 400

@app.route('/endpoint', methods=['GET', 'POST'])
def endpoint():
    return '{"sub": "Keith"}'

@app.route('/token', methods=['POST'])
def token():
    log_header = 'Method=token Transaction=%s' % (request.environ['transaction_id'])
    log.info(log_header + ' Message=Method Called')
    token = ''

    if 'grant_type' in request.form \
            and 'code' in request.form \
            and 'redirect_uri' in request.form \
            and 'client_id' in request.form \
            and 'client_secret' in request.form:

        log.info(log_header + ' Message=Require fields included Form=%s' % request.form)

        if not check_client_auth(request.form['client_id'], request.form['client_secret']):
            log.info(log_header + ' Message=Invalid Client Authentication, returning error Client_ID=%s Client_Secret=%s' % (request.form['client_id'], request.form['client_secret']))
            return json.dumps({'error': 'invalid_client'}), 400

        if not check_code(request.form['code']):
            log.info(log_header + ' Message=Invalid Code, returning error Code=%s' % request.form['code'])
            return json.dumps({'error': 'invalid_grant'}), 400

        if not check_grant_type(request.form['grant_type']):
            log.info(log_header + ' Message=Invalid Grant Type, returning error GrantType=%s' % request.form['grant_type'])
            return json.dumps({'error': 'unsupported_grant_type'}), 400


        log.info(log_header + ' Message=Creating new token request')
        tr = tokenrequest(request.form['grant_type'],
                          request.form['code'],
                          request.form['redirect_uri'],
                          request.form['client_id'],
                          request.form['client_secret'],
                          jwt_expiry_seconds)

        try:
            log.info(log_header + ' Message=Getting token')
            token = tr.get()
        except NonMatchingRedirectException as e:
            log.info(log_header + ' Message=Non-matching Redirect_URI, returning error Code=%s' % request.form['code'])
            return json.dumps({'error': 'invalid_grant'}), 400
        except InvalidCodeException as e:
            log.info(log_header + ' Message=Invalidated Code used Code=%s' % request.form['code'])
            return json.dumps({'error': 'invalid_request'}), 400

        log.info(log_header + ' Message=Returning token Token=%s' % token)
        return token

    else:
        log.info(log_header + ' Message=Required fields not supplied, returning error Form=%s' % request.form)
        return json.dumps({'error': 'invalid_request'}), 400


def check_client_auth(client_id, client_secret=None):
    if client_id not in clients['clients']:
        return False

    stored_client_password_hash = clients['clients'][client_id]

    if stored_client_password_hash == None:
        return False
    else:
        if client_secret != None:
            expected_client_password_hash = hashlib.sha512(('%s.%s' % (client_id, client_secret)).encode('utf-8')).hexdigest()

            if expected_client_password_hash == stored_client_password_hash:
                return True

            return False

    return True

def check_code(code):
    if len(code) != 16:
        return False

    if storage.get('sessions_%s' % code) == None:
        return False

    return True

def check_grant_type(grant_type):
    return grant_type == 'authorization_code'

def check_scope(scope):
    return 'openid' in scope

def check_response_type(response_type):
    return response_type == 'code'

def check_state(state):
    return len(state) > 0 and len(state) < 1024

def get_all_fields(request):
    fields = {}
    accepted_keys = ['client_id',
                     'client_secret',
                     'code',
                     'grant_type',
                     'nonce',
                     'redirect_uri',
                     'response_type',
                     'scope',
                     'state']

    for key, value in request.args.items():
        if key.lower() in accepted_keys:
            fields[key.lower()] = value

    for key, value in request.form.items():
        if key.lower() in accepted_keys:
            fields[key.lower()] = value

    return fields

def loadconfig(type):
    SCRIPTPATH = os.path.dirname(os.path.realpath(__file__))
    with open('/etc/hippo-idp/' + type + '.yml') as cfgstream:
        config = yaml.load(cfgstream)
        return config

class InvalidTokenRequest(Exception):
    pass

class ClientAuthenticationFailure(Exception):
    pass


log = logging.getLogger('idp')

config = loadconfig('config')
clients = loadconfig('clients')

redis_port = config['sessionstore']['port']
redis_address = config['sessionstore']['address']
idservice = config['idservice']['address']
jwt_expiry_seconds = config['session']['jwtexpiryseconds']

storage(redis_address, redis_port)


