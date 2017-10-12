# Import flask and template operators
from flask import Flask, jsonify, render_template

# Import a module / component using its blueprint handler variable (mod_auth)
from .users.controllers import site
from .db_interactions.controllers import admin, engineer

# Define the WSGI application object
app = Flask(__name__)

# Configurations
# app.config.from_object('config.DevelopmentConfig')
app.config.from_object('config.HerokuConfig')


##############
# Blueprints #
##############

# Register blueprint(s)
app.register_blueprint(site)
app.register_blueprint(admin, url_prefix='/admin')
app.register_blueprint(engineer, url_prefix='/engineer')


##################
# Error Handling #
##################


class UnexpectedData(Exception):
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv


@app.errorhandler(UnexpectedData)
def handle_unexpected_data(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


# Sample HTTP error handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
