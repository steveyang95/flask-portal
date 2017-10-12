from flask import Blueprint

# Define the blueprint: 'auth', set its url prefix: app.url/auth
admin = Blueprint('admin', __name__, url_prefix='/admin')
engineer = Blueprint('engineer', __name__, url_prefix='/engineer')