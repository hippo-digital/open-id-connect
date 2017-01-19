from view import app
import logging

app.config['SESSION_TYPE'] = 'filesystem'

log = logging.getLogger('ldap')
log.setLevel(logging.DEBUG)
fh = logging.FileHandler('ldap.log')
fh.setLevel(logging.DEBUG)
log.addHandler(fh)
formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
fh.setFormatter(formatter)
log.info("Run server started")

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5001, threaded=True)


