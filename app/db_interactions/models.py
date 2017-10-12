import aws_qa
import datetime


class DatabaseInteractor:
    def __init__(self):
        self.sdbhelper = aws_qa.SimpleDbHelper()
        self._tables = ['beer-dev-subscriptions']

    def approve_requests(self, domain_name, items):
        """Delete specified entry(ies) from DynamoDB table and SimpleDB.
        This method can do batch deletions, so

        Body:
            [ { 'table' : <string>,
                'primaryKeyVal' : <string>, 'sortKeyVal' : <string>,
                'primaryKey' : <string>, 'sortKey' : <string>
                },
            ],

        The request body/query string must be a dictionary with the keys as the SimpleDB Item Name (userid)
        and the values are lists of dictionaries. 'keys' refers to the DynamoDB table's primary key and sort key.
        If there is no sort key, then input empty string as the value or do not include it in body.

        primaryKey is the table's primary key name. Ex: userid
        sortKey is the table's sort key name. Ex: subscriptionid
        primaryKeyVal is the value for the primaryKey. Ex: test@nubeva.com
        sortKeyVal is the value for the sortKey. Ex: nu-1234567891234

        :return:
        """
        failed_requests = []    # Failed delete requests
        attrs = []              # Successfully deleted attributes

        # Iterate through all delete requests
        for item in items:
            print("\nHere is an item: {}".format(item))
            if 'sortKeyVal' in item:
                keys = '{}|{}'.format(item['primaryKeyVal'], item['sortKeyVal'])
            elif 'primaryKeyVal' in item:
                keys = '{}|'.format(item['primaryKeyVal'])

            table = item['table']

            # Check if there is a delete request in SimpleDB
            try:
                resp = self._request_exist(table, domain_name, keys)
            except Exception as e:
                print('Server::DeleteEntry: {}'.format(e))
                failed_requests.append({'request': keys, 'error': e})

            if 'Items' in resp:
                table_name = self._translate_name_for_sdb(table)

                resp_item = resp['Items'][0]  # Get first item. Technically, there should only be 1
                resp_attrs = resp_item['Attributes']
                item_name = resp_item['Name']
                for attr in resp_attrs:
                    if keys in attr['Value'] and attr['Name'] == table_name:
                        attribute = {'Name': table_name, 'Value': attr['Value']}
                        break
            else:
                message = 'There is no such delete request made {}. ' \
                          'If you would like to force delete, please use the admin override delete option'.format(keys)
                # set_outgoing_resp(req, 400, message)
                failed_requests.append({'request': keys, 'error': message})
                continue

            # Delete request entry from SimpleDB
            try:
                print('\nServer::DeleteEntry: Deleting following attribute from SimpleDB: {}'.format(attribute))
                resp = self.sdbhelper.delete_attributes(domain_name, item_name, [attribute])
            except Exception as e:
                print('Server::DeleteEntry: {}'.format(e))
                failed_requests.append({'request': keys, 'error': e})
                continue

            # Delete entry from DynamoDB table
            try:
                keymap = {item['primaryKey']: item['primaryKeyVal'], item['sortKey']: item['sortKeyVal']}
                print("Server::DeleteEntry::Delete Keymap: {}".format(keymap))

                backend_name, stage, label = self._parse_tablename(table)
                dbhelper = aws_qa.DynamoDbHelper(backend_name, stage, label)
                resp = dbhelper.delete_item(keymap)
                attrs.append(attribute)
            except Exception as e:
                print('Server::DeleteEntry: {}'.format(e))
                failed_requests.append({'request': keys, 'error': e})

        return {'requests': attrs, 'failed_requests': failed_requests}

    def retrieve_delete_requests(self, domain_name, user_email, is_admin):
        """Retrieve all requests either related to the user_email or all requests.
        The requests are from the SimpleDB.

        :param domain_name:
        :param user_email:
        :param is_admin:
        :return:
        """
        query = 'select * from `{}`'.format(domain_name)
        if not is_admin:
            query = 'select * from `{}` where itemName()="{}"'.format(domain_name, user_email)

        print('\nGetDeleteRequests: Starting query: {}'.format(query))
        response = self.sdbhelper.select(query)
        items = []
        if 'Items' in response:
            for item in response['Items']:
                if not is_admin:
                    items += item['Attributes']
                else:
                    items.append((item['Name'], item['Attributes']))
        return items

    def remove_simpledb_requests(self, entries, domain_name, is_admin, user_email):
        """Remove requests from SimpleDB.

        :param entries: (list) if admin, entry format is (SimpleDB item_name, attribute)
                               if regular user, each entry is a SimpleDB attribute
                               An attribute has the SimpleDB attribute format: { 'Name': str, 'Value': str }
        :param is_admin: (bool) if user is admin
        :param domain_name: (str) SimpleDB Domain that entries should be removed from.
        :param user_email: (str) User's email. If not admin, the user's email is the SimpleDB Domain name.
        :return:
        """
        if is_admin:
            for entry in entries:
                item_name, attribute = entry
                self.sdbhelper.delete_attributes(domain_name, item_name, [attribute])
        else:
            self.sdbhelper.delete_attributes(domain_name, user_email, entries)

    def submit_delete_requests(self, table, email, items):
        """Creates the delete requests in SimpleDB.
        If the request already exists or if it fails, the function returns back the request made.

        Helper function for:
            - create_delete_requests()

        :param table:
        :param email:
        :param items:
        :return: (dict) { 'requests': list, 'existing_requests': list, 'failed_requests': list }
        """
        # domain_name = 'DeleteRequests'                # TODO: Cleanup
        domain_name = 'requests'

        # Create domain in SimpleDB if it doesn't exist
        if not self._domain_exist(domain_name):
            print('Server::DeleteEntry: Creating nonexistent domain {}'.format(domain_name))
            self.sdbhelper.create_domain(domain_name)

        attrs = []  # Attributes to be put in SimpleDB
        existing_requests = []  # Existing requests already found in SimpleDB
        failed_requests = []  # Failed delete requests
        current_time = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SUTC")

        # Iterate through all delete requests. read_content must be a Python dict
        for item in items:
            print("\nHere is an attribute: {}".format(item))
            keys = '{}|'.format(item['primaryKey'])
            if 'sortKey' in item:
                keys = '{}|{}'.format(item['primaryKey'], item['sortKey'])
            resp = None

            # Check if there is a delete request in SimpleDB
            try:
                resp = self._request_exist(table, domain_name, keys)
            except Exception as e:
                print('Server::CreateDeleteRequest: {}'.format(e))
                failed_requests.append({'request': keys, 'error': e})

            # Add delete request to SimpleDB if it does not already exist
            print('\nCreateDeleteRequest: Query response: {}'.format(resp))
            if 'Items' in resp:
                # Form (Name of person who already made request, request)
                existing_requests.append({resp['Items'][0]['Name']: keys})
            else:
                value = '{}|{}'.format(keys, current_time)
                print('\nCreateDeleteRequest: Attr Value: {}'.format(value))
                attrs.append({'Name': self._translate_name_for_sdb(table), 'Value': value})

        print("Server::CreateDeleteRequest::Attrs: {}\n".format(attrs))
        if attrs:
            self.sdbhelper.put_attributes(domain_name, email, attrs)

        return {'requests': attrs, 'existing_requests': existing_requests, 'failed_requests': failed_requests}

    def get_table_keys(self, table_name):
        """Retrieves the DynamoDB Table Keys for the table specified.

        :param table_name:
        :return: (dict)
        """
        table_name = self._translate_name_for_dynamodb(table_name)
        backend_name, stage, label = self._parse_tablename(table_name)
        dbhelper = aws_qa.DynamoDbHelper(backend_name, stage, label)
        return dbhelper.get_table_keys(table_name)

    def retrieve_entries_from_tablename(self, table_name):
        """Returns all entries in the DynamoDB table.

        :param table_name:
        :return:
        """
        table_name = self._translate_name_for_dynamodb(table_name)
        backend_name, stage, label = self._parse_tablename(table_name)
        dbhelper = aws_qa.DynamoDbHelper(backend_name, stage, label)
        return dbhelper.get_table_entries()

    def get_dynamodb_tables(self):
        """List of available tables that can be accessed by users.

        :return:
        """
        return self._tables

    def create_delete_request_keymap(self, entries, table):
        """Creates a keymap for all entries input to this function.
        Keymap is needed for the delete request that will be made.
        Simplifies the process for creating format when inserting to SimpleDB.

        Helper Function for:
            - create_delete_requests()

        :param entries:
        :param table:
        :return: (list)
        """
        # Get keys for specific table
        keys = self.get_table_keys(table)

        items = []
        # Create multiple payloads
        for entry in entries:
            # Create Keymap for Delete Request
            keymap = self._create_dynamo_keymap(keys, entry)
            items.append(keymap)
        return items

    def create_approve_request_keymap(self, entries):
        """Creates a keymap so that it is easier to build DynamoDB payloads and SimpleDB payloads.

        :param entries: (list) Each entry is of format (SimpleDB item_name, SimpleDB attribute)
                               A SimpleDB attribute is of format { 'Name': str, 'Value': str }
        :return: (list)
            [ { 'table' : <string>,
                'primaryKeyVal' : <string>, 'sortKeyVal' : <string>,
                'primaryKey' : <string>, 'sortKey' : <string>
                }, ],
        """
        cached_keys = {}
        items = []
        # Iterate through and create the payload
        for entry in entries:
            payload = {}

            # entry is of format (SimpleDB item_name, SimpleDB attribute)
            item_name, attribute = entry
            table = attribute['Name']                   # tablename is in SimpleDB format with '_' instead of '-'
            primary_key_val, sort_key_val, timestamp = attribute['Value'].split('|')

            # Create DynamoDB table keymap of primary and sort key. Reduces # of get_table_keys() request to server
            if table not in cached_keys:
                keys = self.get_table_keys(table)
                cached_keys[table] = self._create_approve_request_keymap_helper(keys)

            # Create payload to send delete request
            payload['table'] = table
            payload['primaryKey'] = cached_keys[table]['primaryKey']  # There must always be a primaryKey
            payload['primaryKeyVal'] = primary_key_val
            payload['sortKey'] = cached_keys[table]['sortKey'] if 'sortKey' in cached_keys[table] else ''
            payload['sortKeyVal'] = sort_key_val
            items.append(payload)

        return items

    def _create_dynamo_keymap(self, keys, entry):
        """Creates a keymap with the DynamoDB primaryKey (and sortKey when available).
        This method requires the DynamoDB entry and maps the keys "primaryKey" and "sortKey"
        with the actual values of the primaryKey and sortKey.

            { "primaryKey" : "string", "sortKey" : "string" }

        Example:
            { "primaryKey" : "syang@nubeva.com", "sortKey" : "nu-1234567890" }

        :param keys: (dict) Dictionary of DynamoDB key mapping
        :param entry: (dict) DynamoDB entry response
        :return:
        """
        keymap = {}
        for key in keys:
            key_type = key['KeyType']
            if key_type == "HASH":
                keymap['primaryKey'] = entry[key['AttributeName']]
            elif key_type == "RANGE":
                keymap['sortKey'] = entry[key['AttributeName']]
            else:
                raise ValueError("DBCLI::Unknown AWS DynamoDB Key Type.")
        return keymap

    def _create_approve_request_keymap_helper(self, keys):
        """Creates a keymap with the DynamoDB primaryKey (and sortKey when available).
        This method maps the keys "primaryKey" and "sortKey" with the name of the primaryKey and sortKey.

        { "primaryKey" : "string", "sortKey" : "string" }

        Example:
            { "primaryKey" : "userid", "sortKey" : "subscriptionid" }

        :param keys: (dict)
        :return:
        """
        keymap = {}
        for key in keys:
            key_type = key['KeyType']
            if key_type == "HASH":
                keymap['primaryKey'] = key['AttributeName']
            elif key_type == "RANGE":
                keymap['sortKey'] = key['AttributeName']
            else:
                raise ValueError("DBCLI::Unknown AWS DynamoDB Key Type.")
        return keymap

    def _parse_tablename(self, table_name):
        """Parses tablename into backend, stage, and label.
        Tablename can either be in SimpleDB format or DynamoDB format:
            SimpleDB format:
                <backend>_<stage>_<label>
            DynamoDB format:
                <backend>-<stage>-<label>

        Constraints:
            Expects all table names to have at least 3 parts: backend, stage, and label

            INPUT:
                table_name (str) : Table name of the format <backend>-<stage>-<label>

            OUTPUT:
                tuple : (backend, stage, label)
        """
        table_name = self._translate_name_for_dynamodb(table_name)
        tokens = table_name.split('-')
        backend_name = tokens[0]
        stage = tokens[1]
        label = tokens[2] if len(tokens) == 3 else '{}-{}'.format(tokens[2], tokens[3])
        return backend_name, stage, label

    def _translate_name_for_sdb(self, name):
        """In order to make queries in SimpleDB, the Name field cannot have '-'.
        So this method changes all '-' to '_'

        :param name:
        :return:
        """
        return '_'.join(name.split('-'))

    def _translate_name_for_dynamodb(self, name):
        """Translates name to be used for dynamodb.

        <backend>-<stage>-<label>

        :param name:
        :return:
        """
        return '-'.join(name.split('_'))

    def _request_exist(self, table, domain_name, keys):
        """Query SimpleDB Domain to see if an item exists

        :param table: (str) tablename
        :param domain_name: (str) SimpleDB Domain Name
        :param keys: (str)
        :return: (dict) response of the SimpleDB select method
        """
        tablename = self._translate_name_for_sdb(table)

        # Query: SimpleDB Queries cannot have '-'. Need to be '_'
        # Make sure that nobody has made same request
        query = "select * from {0} where {1} like '{2}%'".format(domain_name, tablename, keys)

        print('\nCreateDeleteRequest: Starting query: {}'.format(query))
        return self.sdbhelper.select(query)

    def _domain_exist(self, domain_name):
        """Check if the domain exists in the AWS account.

        :param domain_name:
        :return:
        """
        return self.sdbhelper.get_domain_metadata(domain_name) is not None
