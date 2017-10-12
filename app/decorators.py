from functools import wraps

from flask import redirect, url_for, session, flash

from .functions import validate_is_admin
from .functions import get_google_credentials_from_session, get_email_from_session


def login_required(f):
    """General Login Decorator. Makes sure user is logged in with GMail.

    :param f:
    :return:
    """
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'credentials' not in session:
            flash("You need to login with a Google account")
            return redirect(url_for('site.login'))

        credentials = get_google_credentials_from_session(session['credentials'])
        if credentials.access_token_expired:
            flash("Please log back in. Your access token has expired.")
            return redirect(url_for('site.login'))
        if '@nubeva.com' not in get_email_from_session(session):
            flash("Please log back in with a Nubeva company account.")
            return redirect(url_for('site.homepage'))
        return f(*args, **kwargs)
    return wrap


def is_admin(f):
    """Checks if Nubeva admin decorator. Must be admin in order to execute function

    :param f:
    :return:
    """
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'credentials' not in session:
            flash("Please log in")
            return redirect(url_for('site.login'))
        credentials = get_google_credentials_from_session(session['credentials'])
        if credentials.access_token_expired:
            flash("Please log back in. Your access token has expired.")
            return redirect(url_for('site.login'))
        if '@nubeva.com' not in get_email_from_session(session):
            flash("Please log back in with a Nubeva company account.")
            return redirect(url_for('site.homepage'))

        if not validate_is_admin(credentials):
            return redirect(url_for('site.engineer_home'))

        return f(*args, **kwargs)
    return wrap


def is_engineer(f):
    """Checks if Nubeva engineer decorator. Must be engineer in order to execute function.

    :param f:
    :return:
    """
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'credentials' not in session:
            flash("Please log in")
            return redirect(url_for('site.login'))
        credentials = get_google_credentials_from_session(session['credentials'])
        if credentials.access_token_expired:
            flash("Please log back in. Your access token has expired.")
            return redirect(url_for('site.login'))
        if '@nubeva.com' not in get_email_from_session(session):
            flash("Please log back in with a Nubeva company account.")
            return redirect(url_for('site.homepage'))

        if validate_is_admin(credentials):
            return redirect(url_for('site.admin_home'))

        return f(*args, **kwargs)

    return wrap
