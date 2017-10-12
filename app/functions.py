import httplib2
import json
import ast

from apiclient import discovery
from oauth2client import client
from googleapiclient.errors import HttpError
from oauth2client.client import HttpAccessTokenRefreshError


def validate_is_admin(credentials):
    """Checks if user can access the Admin SDK Directory API.
    The user will attempt to retrieve the Google Group: "engineering@nubeva.com"

    Google has made it so that only admins of the Google Admin SDK Directory are allowed to make API calls.
    If the user has access, then the user is an admin and should be authorized to perform special operations.

    :return: None

    :raise HttpError: service.groups().get().execute() can raise with message,
                      "Not Authorized to access this resource/api"
    :raise HttpAccessTokenRefreshError: service.people().get().execute() can raise
                                        if token has been revoked or expired
    """
    try:
        print('\nRetrieving the Admin SDK Directory service...')
        http = credentials.authorize(httplib2.Http())
        service = discovery.build('admin', 'directory_v1', http=http)

        print('Retrieving group...')
        group_document = service.groups().get(groupKey='engineering@nubeva.com').execute()
        # group_document = service.groups().get(groupKey='dbserver@nubedge.com').execute()
    except HttpError as e:
        print('\nGoogleApp::ValidateIsAdmin::HttpError: {}'.format(e))
        return False
    except HttpAccessTokenRefreshError as e:
        print('\nGoogleApp::ValidateIsAdmin::HttpAccessTokenRefreshError: {}'.format(e))
        return False

    if group_document:
        print("Group Document: {}".format(group_document))
    return True


def get_google_credentials_from_session(credentials):
    """Returns the Google OAuth2 credentials object.

    :param credentials:
    :return:
    """
    return client.OAuth2Credentials.from_json(credentials)


def get_email_from_session(session):
    """Returns the email.

    Currently only gets the Google Email. Can be changed if other logins allowed.

    :param session:
    :return:
    """
    return session['google_id_token']['email']


def check_if_admin_with_session(session):
    """Use the Flask session object to check if the user is an admin.

    :param session:
    :return:
    """
    credentials = get_google_credentials_from_session(session['credentials'])
    return validate_is_admin(credentials)


def convert_request_to_python_obj(entries):
    """After POST in Flask, the results are given back as strings with single quotes.
    But in order to convert an object to JSON or a python object, we need to convert
    the single quotes to double quotes.

    :param entries:
    :return:
    """
    return [json.loads(json.dumps(ast.literal_eval(entry))) for entry in entries]
