from flask import Flask, request
from ldap_authenticator import ldap_authenticator
import logging, os
import yaml
import string
import hashlib
import random
import json


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
                # request.form,
                request.data.decode('utf-8')))

@app.route('/getuserdetails', methods=['POST'])
def getuserdetails():
    log_header = 'Method=getuserdetails Transaction=%s' % (request.environ['transaction_id'])
    log.info(log_header + ' Message=Method Called')

    if 'username' in request.form and 'password' in request.form:
        ret = {}
        log.info(log_header + ' Message=Username/password received Username=%s' % request.form['username'])

        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.md5(password.encode('utf-8')).hexdigest()

        log.info(log_header + ' Message=Username and/or password received Username=%s Password=%s' % (request.form['username'], hashed_password))

        log.info(log_header + ' Message=Validating username/password against LDAP')

        try:
            auth = ldapauth.verify_user(request.environ['transaction_id'], username, password)

            log.info(log_header + ' Message=LDAP validation returned AuthStatus=%s' % auth['success'])

            if not auth['success']:
                log.info(log_header + ' Message=Returning login form with auth failure status')
                return json.dumps({'success': False, 'error': 'authentication_failure', 'error_description': 'Incorrect username and/or password entered, please try again.'}), 400

            ret['success'] = True

            log.info(log_header + ' Message=Setting username claim Username=%s' % username)
            ret['sub'] = username

            log.info(log_header + ' Message=Setting other claims Claims=%s' % auth['claims'])
            ret['claims'] = auth['claims']

            return json.dumps(ret)

        except Exception as e:
            log.error(log_header + ' Message=Failed to authenticate via LDAP', e)
            return json.dumps({'success': False, 'error': 'request_failed',
                    'error_description': 'Unspecified error, see log file for details'}), 400

    else:
        return {'success': False, 'error': 'invalid_request', 'error_description': 'Username and/or password not present'}, 400


def loadconfig(type):
    SCRIPTPATH = os.path.dirname(os.path.realpath(__file__))
    with open('/etc/hippo-ldap/' + type + '.yml') as cfgstream:
        config = yaml.load(cfgstream)
        return config



log = logging.getLogger('ldap')

config = loadconfig('config')

idstore_port = config['idstore']['port']
idstore_address = config['idstore']['address']
idstore_serviceaccountdn = config['idstore']['serviceaccountdn']
idstore_serviceaccountpassword = config['idstore']['serviceaccountpassword']
idstore_basesearchdn = config['idstore']['basesearchdn']
claim_attributes = config['claimattributes']

ldapauth = ldap_authenticator(idstore_address, idstore_port, idstore_serviceaccountdn, idstore_serviceaccountpassword, idstore_basesearchdn, claim_attributes)

