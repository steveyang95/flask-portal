from flask import request, render_template, g, session

from ..decorators import login_required, is_admin
from ..functions import get_email_from_session, convert_request_to_python_obj, check_if_admin_with_session
from .models import DatabaseInteractor

from . import engineer, admin


@engineer.route('/tables')
@admin.route('/tables')
@login_required
def tables_index():
    g.url_prefix = 'admin' if check_if_admin_with_session(session) else 'engineer'
    tables = DatabaseInteractor().get_dynamodb_tables()
    return render_template('tables_index.html', tables=tables)


@engineer.route('/<string:table>-entries', methods=['GET', 'POST'])
@admin.route('/<string:table>-entries', methods=['GET', 'POST'])
@login_required
def table_entries(table):
    if request.method == 'GET':
        # Retrieve all Table Entries
        entries = DatabaseInteractor().retrieve_entries_from_tablename(table)
        return render_template('table_entries.html', table=table, entries=entries)
    elif request.method == 'POST':
        return render_template('404.html')
    return render_template('404.html')


@engineer.route("/delete-requests", methods=['GET', 'POST'])
@admin.route("/delete-requests", methods=['GET', 'POST'])
@login_required
def get_delete_requests():
    """Retrieves delete requests made.

    If regular user, retrieves requests only for that user.
    If admin, retrieves all requests.

    :return:
    """
    # domain_name = 'DeleteRequests'                # TODO: Cleanup
    domain_name = 'requests'

    user_email = get_email_from_session(session)
    is_admin = check_if_admin_with_session(session)

    if request.method == "GET":
        items = DatabaseInteractor().retrieve_delete_requests(domain_name, user_email, is_admin)
        return render_template('delete_requests.html', user_email=user_email, entries=items, is_admin=is_admin)
    elif request.method == "POST":
        # Give option to remove requests
        entries = request.form.getlist("cbentry")
        entries = convert_request_to_python_obj(entries)
        DatabaseInteractor().remove_simpledb_requests(entries, domain_name, is_admin, user_email)
        items = DatabaseInteractor().retrieve_delete_requests(domain_name, user_email, is_admin)
        return render_template('delete_requests.html', user_email=user_email, entries=items, is_admin=is_admin)

    return render_template('404.html')


@engineer.route("/create-delete-requests")
@admin.route("/create-delete-requests")
@login_required
def create_delete_requests_index():
    g.url_prefix = 'admin' if check_if_admin_with_session(session) else 'engineer'
    tables = DatabaseInteractor().get_dynamodb_tables()
    return render_template('create_delete_request_table_index.html', tables=tables)


@engineer.route("/create-delete-requests/<table>", methods=['GET', 'POST'])
@admin.route("/create-delete-requests/<table>", methods=['GET', 'POST'])
@login_required
def create_delete_requests(table):
    if request.method == "POST":
        entries = request.form.getlist("cbentry")
        entries = convert_request_to_python_obj(entries)
        user_email = get_email_from_session(session)

        items = DatabaseInteractor().create_delete_request_keymap(entries, table)
        resp = DatabaseInteractor().submit_delete_requests(table, user_email, items)
        existing_requests = resp['existing_requests']
        return render_template('successful_request.html', existing_requests=existing_requests,
                               failed_requests=resp['failed_requests'], successful_requests=resp['requests'])
    elif request.method == "GET":
        entries = DatabaseInteractor().retrieve_entries_from_tablename(table)
        return render_template('delete_request_form.html', table=table, entries=entries)

    return render_template('404.html')


@admin.route("/approve-requests", methods=['GET', 'POST'])
@is_admin
def approve_requests():
    # domain_name = 'DeleteRequests'                # TODO: Cleanup
    domain_name = 'requests'
    user_email = get_email_from_session(session)
    if request.method == "GET":
        items = DatabaseInteractor().retrieve_delete_requests(domain_name, user_email, is_admin)
        return render_template('approve_requests.html', entries=items)
    elif request.method == "POST":
        entries = request.form.getlist("cbentry")
        entries = convert_request_to_python_obj(entries)
        items = DatabaseInteractor().create_approve_request_keymap(entries)
        resp = DatabaseInteractor().approve_requests(domain_name, items)
        return render_template('successful_request.html', failed_requests=resp['failed_requests'],
                               successful_requests=resp['requests'])
    return render_template('404.html')
