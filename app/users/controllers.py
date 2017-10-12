import json
import gc

from flask import request, render_template, flash, session, redirect, url_for, current_app

from oauth2client import client
from oauth2client.client import OAuth2WebServerFlow

from ..decorators import login_required, is_admin, is_engineer
from ..functions import get_google_credentials_from_session, validate_is_admin, get_email_from_session

from . import site


@site.route('/')
def homepage():
    """Website homepage.

    :return:
    """
    return render_template('home.html')


@site.route('/login')
def login():
    """Logs in user and redirects user to Google OAuth2 Login page.

    :return:
    """
    return redirect(url_for('site.oauth2callback'))


@site.route('/oauth2callback')
def oauth2callback():
    """Google OAuth2 Authentication. Redirects user to engineer or admin portal.

    :return:
    """
    flow = OAuth2WebServerFlow(client_id=current_app.config.get('GOOGLE_ID'),
                               client_secret=current_app.config.get('GOOGLE_SECRET'),
                               scope=current_app.config.get('GOOGLE_SCOPE'),
                               redirect_uri=url_for('site.oauth2callback', _external=True))
    if 'code' not in request.args:
        auth_uri = flow.step1_get_authorize_url()
        return redirect(auth_uri)
    else:
        auth_code = request.args.get('code')
        credentials = flow.step2_exchange(auth_code)
        session['credentials'] = credentials.to_json()
        # for Google OAuth Credentials object
        session['google_id_token'] = json.loads(session['credentials'])['id_token']
        credentials = client.OAuth2Credentials.from_json(session['credentials'])

        if credentials.access_token_expired:
            flash("Please log back in. Your access token has expired.")
            return redirect(url_for('site.login'))
        if '@nubeva.com' not in get_email_from_session(session):
            flash("Please log back in with a Nubeva company account.")
            return redirect(url_for('site.homepage'))
        return redirect(url_for('site.portal'))


@site.route('/logout')
@login_required
def logout():
    """Logs out the user and removes session.

    :return:
    """
    session.pop('credentials', None)
    flash("You have been logged out!")
    gc.collect()
    return redirect(url_for('site.homepage'))


@site.route('/portal')
@login_required
def portal():
    """Redirects user to the correct portal page based on user being engineer or admin.

    :return:
    """
    credentials = get_google_credentials_from_session(session['credentials'])
    try:
        validate_is_admin(credentials)
    except Exception:
        return redirect(url_for('site.engineer_home', data=session['credentials']))
    else:
        return redirect(url_for('site.admin_home'))


@site.route('/engineer')
@is_engineer
def engineer_home():
    """Redirects to engineer portal.

    :return:
    """
    return render_template('engineer_home.html')


@site.route('/admin')
@is_admin
def admin_home():
    """Redirects to admin portal.

    :return:
    """
    return render_template('admin_home.html')
