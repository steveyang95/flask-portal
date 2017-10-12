from __future__ import print_function

import boto3
import jmespath
import pprint
import time

from botocore.exceptions import ClientError

from flask import current_app

# Globals
pp = pprint.PrettyPrinter(indent=4)


#######
# EC2 #
#######


class EC2Helper(object):
    """This is a ec2 helper class

    Attributes:
        client
    """

    def __init__(self, profile="default", region="us-west-2"):
        """Initializes the ec2 client helper.
            INPUT:
                profile (str) : AWS Profile
                                REQUIRED
                region (str)  : AWS REGION
                                REQUIRED
        """
        boto3.setup_default_session(aws_access_key_id=current_app.config.get('AWS_ACCESS_KEY_ID'),
                                    aws_secret_access_key=current_app.config.get('AWS_SECRET_ACCESS_KEY'),
                                    region_name=region)
        # boto3.setup_default_session(profile_name=profile, region_name=region)
        self.client = boto3.client('ec2')

    def pa_exist(self, subid):
        """Checks if the Palo Alto for the specified subid exists.
            INPUT:
                subid (str) : SE Subscription ID
            OUTPUT:
                bool : True if PaloAlto exists, False if terminated or nonexistent
        """
        name = 'PaloAlto-{}'.format(subid)
        resp = self.find_instance_with_name(name)
        try:
            instances = resp['Reservations'][0]['Instances']
        except Exception:
            print('\n{} does not exist'.format(name))
            return False
        else:
            if instances[0]['State']['Name'] == "terminated":
                print('\n{} in terminated state'.format(name))
                return False
            print('Found {} in response:\n{}'.format(name, resp))
            pp.pprint(instances)
            return True

    def dispatcher_exist(self, subid):
        """Checks if the Dispatcher for the specified subid exists.
            INPUT:
                subid (str) : SE Subscription ID
            OUTPUT:
                bool : True if Dispatcher exists, False if terminated or nonexistent
        """
        name = 'Dispatcher-{}'.format(subid)
        resp = self.find_instance_with_name(name)
        try:
            instances = resp['Reservations'][0]['Instances']
        except Exception:
            print('\n{} does not exist'.format(name))
            return False
        else:
            if instances[0]['State']['Name'] == "terminated":
                print('\n{} in terminated state'.format(name))
                return False
            print('Found {} in response:\n{}'.format(name, resp))
            pp.pprint(instances)
            return True

    def find_instance_with_name(self, name):
        """Finds the correct ec2 instance with the name given.
            INPUT:
                name (str) : Name of the ec2 instance
                             This name refers to the ec2 tag:Name
                             REQUIRED
            OUTPUT:
        """
        resp = self.client.describe_instances(
            Filters=[
                {
                    'Name': 'tag:Name',
                    'Values': [name]
                },
            ]
        )
        return resp


#######
# ECS #
#######


class ECSHelper(object):
    """This is a ecs helper class

    Attributes:
        client
    """

    def __init__(self, profile="default", region="us-west-2"):
        """Initializes the ECS client helper.
            INPUT:
                profile (str) : AWS Profile
                                REQUIRED
                region (str)  : AWS REGION
                                REQUIRED
        """
        boto3.setup_default_session(aws_access_key_id=current_app.config.get('AWS_ACCESS_KEY_ID'),
                                    aws_secret_access_key=current_app.config.get('AWS_SECRET_ACCESS_KEY'),
                                    region_name=region)
        # boto3.setup_default_session(profile_name=profile, region_name=region)
        self.client = boto3.client('ecs')

    def list_clusters(self):
        """Retrieves all the ECS clusters.
            OUTPUT:
                list : List of cluster ARNS of the following format:
                           arn:aws:ecs:<region>:<aws_account_id>:cluster/<cluster_name>
        """
        resp = self.client.list_clusters()
        cluster_arns = resp['clusterArns'] if 'clusterArns' in resp else []
        while 'nextToken' in resp:
            resp = self.client.list_clusters(nextToken=resp['nextToken'])
            cluster_arns += resp['clusterArns']
        return cluster_arns

    def describe_services(self, service, cluster):
        """Returns the description of the service specified.
        If no service found, return None.
            INPUT:
                service (str) : Service Name
                                REQUIRED
            OUTPUT:
                dict : Service descriptions
        """
        try:
            resp = self.client.describe_services(
                cluster=cluster,
                services=[service]
            )
        # NOTE: Should have more specific error handling in the future
        except Exception as e:
            print('AWSQA::ECSHelper::DescribeServices: {}'.format(e))
            return {}
        else:
            return resp['services'][0]

    def nim_exists(self, subid, cluster):
        """Checks if nim exists.
            INPUT:
                subid (str) : SE Subscription ID
                              REQUIRED
            OUTPUT:
                bool : True if NIM exists, else False
        """

        nim = 'nim-{}'.format(subid)
        service = self.describe_services(nim, cluster)
        not_deleting = (service and service['status'] != "DRAINING"
                        and service['status'] != "DELETING")
        if not_deleting:
            return True
        return False


##################
# CloudFormation #
##################


class CloudFormationHelper(object):
    """This is a CloudFormation helper class

    Attributes:
        client
    """

    def __init__(self, profile="default", region="us-west-2", credentials=None):
        """Initializes the CloudFormation client helper.
            INPUT:
                profile (str) : AWS Profile
                                OPTIONAL: defaults to "default"
                region (str)  : AWS REGION
                                OPTIONAL: defaults to "us-west-2"
        """
        if credentials:
            self.client = boto3.client(
                'cloudformation',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
        else:
            boto3.setup_default_session(aws_access_key_id=current_app.config.get('AWS_ACCESS_KEY_ID'),
                                        aws_secret_access_key=current_app.config.get('AWS_SECRET_ACCESS_KEY'),
                                        region_name=region)
            # boto3.setup_default_session(profile_name=profile, region_name=region)
            self.client = boto3.client('cloudformation')
            """ :type: pyboto3.cloudformation """

    def get_template(self, stackname):
        """Retrieves the Cloudformation template with the given stackname.
        If template does not exist, then ValidationError raised.

            INPUT:
                stackname (str) : CloudFormation stack name
                                  REQUIRED
            OUTPUT:
                dict : {
                           'TemplateBody': {},
                           'StagesAvailable': [
                               'Original'|'Processed',
                           ]
                       }
        """
        try:
            resp = self.client.get_template(
                StackName=stackname,
            )
        # NOTE: Should have more specific error handling in the future
        except Exception as e:
            raise e
        else:
            return resp

    def get_stacks(self, stackid="", nexttoken=""):
        """Retrieves the CloudFormation stacks that match the given name. If the
        template does not exist, then a ValidationError is raised.

            INPUT:
                stackname (str) : CloudFormation stack name or unique ID to be fetched
                                  OPTIONAL: if not defined, all stacks are fetched

                nexttoken (str) : A string that identifies the next page of stacks
                                  that you want to retrieve.
                                  OPTIONAL: if not defined, it will not advance to the
                                  next page of responses

            OUTPUT: http://boto3.readthedocs.io/en/latest/reference/services/cloudformation.html#CloudFormation.Client.describe_stacks

                dict : {
                           'Stack': [ ... dict(s) ...  ]
                           'NextToken': 'String'
                       }
        """
        try:
            if nexttoken:
                resp = self.client.describe_stacks(
                    StackName=stackid,
                    NextToken=nexttoken
                )
            else:
                resp = self.client.describe_stacks(StackName=stackid)
        # NOTE: Should have more specific error handling in the future
        except Exception as e:
            print('CloudFormationHelperException::{}'.format(e))
            return {}
        else:
            return resp

    def get_outputs(self, stackname):
        """Retrieves the ouputs of the CloudFormation stack that matches the
        given name. If the template does not exist, then a ValidationError is
        raised.

            INPUT:
                stackname (str) : CloudFormation stack name
                                  REQUIRED

            OUTPUT:
                list : [
                    ...
                    {
                        'OutputKey': string of output name,
                        'OutputValue': name/arn of the named resoruce
                    }
                    ...
                ]
        """

        try:
            resp = self.get_stacks(stackname)['Stacks'][0]['Outputs']
        # NOTE: Should have more specific error handling in the future
        except Exception as e:
            raise e
        else:
            return resp

    def cf_resources_deleted(self, subid):
        """Checks that all SE CloudFormation Resources have been removed.
            INPUT:
                subid (str) : SE Subscription ID
                              REQUIRED
            OUTPUT:
                bool : True if resources removed, else False
        """
        subidnum = subid[3:]
        pa = "pa-a-{}".format(subidnum)
        dispatcher = "nu-{}".format(subidnum)

        pa_exists = False
        dispatcher_exists = False
        try:
            pa_exists = self.get_template(pa)
        except:
            print("Palo Alto CloudFormation Stack with id {} successfully deleted".format(pa))
        try:
            dispatcher_exists = self.get_template(dispatcher)
        except:
            print("Dispatcher CloudFormation Stack with id {} successfully deleted".format(dispatcher))

        if not pa_exists and not dispatcher_exists:
            return True
        return False

    def output_keyvalue(self, keyval, outputs):
        """Used for fetching values from the Outputs list of a CloudFormation
        Outputs list. Iterates through the list of dictionaries, finds the
        dictionary where the value associated to "OutputKey" entry == keyval,
        and returns the field "OutputValue".

            INPUT:
                keyval (str) : the key value to match for the
                               REQUIRED

                outputs (list) : a list of output dictionary objects. Expected
                                 to be the outputs from the CloudFormation template
                                 REQUIRED

            OUTPUT:
                str : the field "OutputValue" if Outputs contains keyval.

            RAISES:
                LookupError : when no output containing the keyval exists in outputs
        """

        for output in outputs:
            if output["OutputKey"] == keyval:
                return output["OutputValue"]
        print('No matching output found')
        raise LookupError("No output in outputs contains the keyval")

    def launch_url(self, url, name):
        """
        Launches a CloudFormation Template using a S3 bucket URL. Waits for completion. Returns True
        IFF the launch is a success.
        :param url: str - the url of the CloudFormation template to use
        :param name: str - the name of the CloudFormation Stack
        :return: bool
        """
        # uid = re.split("[\W+]", url)[-2]  # should be last chunk of the user UUID
        try:
            self.client.create_stack(
                StackName=name,
                TemplateURL=url,
                TimeoutInMinutes=5,  # by nick's experience should take less than this.
                OnFailure='DELETE',  # search through deleted cloudformation stacks to find the right value.
                Capabilities=['CAPABILITY_NAMED_IAM'])
        except ClientError as b3er:
            print("Create Failed:\nStackName = {}\n URL = {}".format(name, url))
            raise b3er

        lnc_wt = self.client.get_waiter('stack_create_complete')
        try:
            lnc_wt.wait(StackName=name)
        except ClientError as b3er:
            print(str(b3er))
            return False
        return True

    def list_events(self, name):
        """ Lists the events of a Cloudformation Stack"""
        res = self.client.describe_stack_events(StackName=name)
        events = jmespath.search('StackEvents[]', res)
        nextT = jmespath.search('NextToken', res)
        pp.pprint(events)
        while nextT:
            res = self.client.describe_stack_events(StackName=name, NextToken=nextT)
            events = jmespath.search('StackEvents[]', res)
            nextT = jmespath.search('NextToken', res)
            pp.pprint(events)

    def delete_name(self, name):
        """ Deletes a CloudFormation stack by name. Returns True IFF the delete is complete. Prints some debug
        information if the creation fails.
        :param name: str the name of the cloudformation stack to delete
        :param success: bool whether the cloudformation stack launched correctly or not
        :returns: bool
        """
        try:
            self.client.delete_stack(StackName=name)
        except ClientError as b3er:
            print('Delete failed:\nName :{}'.format(name))
            raise b3er

        del_wt = self.client.get_waiter('stack_delete_complete')
        try:
            del_wt.wait(StackName=name)
        except ClientError as b3er:
            print(str(b3er))
            return False
        return True


############
# DynamoDb #
############


class DynamoDbHelper(object):
    def __init__(self, backendname, stage, table_suffix=None, region="us-west-2"):
        """Initialize DynamoDb Helper Class.
        INPUTS:
            backendname (str)  : The name of the backend to be queried.
                                 REQUIRED
            stage (str)        : The stage of the backend to be queried.
                                 REQUIRED
            table_suffix (str) : Allowed DynamoDb Table Suffix names:
                                 (users, subscriptions, global-resources, keys)
                                 OPTIONAL
            region (str)       : Name of AWS DynamoDb Region.
                                 Default is "us-west-2"
                                 OPTIONAL
        """
        boto3.setup_default_session(aws_access_key_id=current_app.config.get('AWS_ACCESS_KEY_ID'),
                                    aws_secret_access_key=current_app.config.get('AWS_SECRET_ACCESS_KEY'),
                                    region_name=region)
        self.db_client = boto3.client('dynamodb', region_name=region)
        self.region = region
        self.table_name, self.table = None, None
        if backendname and stage and (table_suffix in ["users", "subscriptions", "global-resources", "keys"]):
            self.table_name = "{0}-{1}-{2}".format(backendname, stage, table_suffix)
        if self.table_name:
            self.table = boto3.resource("dynamodb", region_name=region).Table(self.table_name)

    def change_table(self, backendname, stage, table_suffix, region):
        """Changes classes DynamoDB Table to new one specified through input parameters.

        :param backendname: (str)
        :param stage: (str)
        :param table_suffix: (str)
        :param region: (str)
        :return: (bool) True if successfully changed table
        """
        self.region = region
        self.table_name = "{0}-{1}-{2}".format(backendname, stage, table_suffix)
        self.table = boto3.resource("dynamodb", region_name=self.region).Table(self.table_name)
        return True

    def get_table_keys(self, table_name=None):
        """Retrieves all the keys from the table.
            INPUT:
                table_name (str)   : Table name to retrieve keys from
                                    REQUIRED

            OUTPUT:
                list : Returns a list of table keys
        """
        if not table_name:
            table_name = self.table_name
        resp = self.db_client.describe_table(
            TableName=table_name
        )
        # return [attribute['AttributeName'] for attribute in resp['Table']['KeySchema']]
        return resp['Table']['KeySchema']

    def get_table_entries(self):
        """Retrieves all entries from DynamoDB table.
            INPUT:
                table (obj)  : DynamoDB table
                               REQUIRED

            OUTPUT:
                list : A list of table entries
        """
        table = self.table
        try:
            resp = table.scan()
            entries = resp['Items']

            while 'LastEvaluatedKey' in resp:
                resp = table.scan(ExclusiveStartKey=resp['LastEvaluatedKey'])
                entries += resp['Items']
        except Exception as e:
            print('\nAWSQA::Dynamo::GetTableEntries: {}'.format(e))
            self.get_helper_info()
        else:
            return entries

    def delete_item(self, key, retry_count=5):
        """Deletes item with key input.
        Tries 5 times before raising a KeyError.

            INPUTS:
                key (dict):       Dictionary of the entry that will be deleted from the db
                                  REQUIRED
                retry_count (int): # of retries allowed if request failed
                                  REQUIRED

            OUTPUTS:
                response (dict): Dictionary of the response given from delete request

            Raises:
                KeyError : Item with specified key cannot be deleted.
        """
        response = None
        for i in range(retry_count):
            response = self.table.delete_item(Key=key)
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                break
            time.sleep(1)
            print(
                "Retry #{} response returned {} - {}".format(i + 1, response['ResponseMetadata']['HTTPStatusCode'],
                                                             response))
        if response['ResponseMetadata']['HTTPStatusCode'] != 200:
            raise KeyError("AWSQA::Dynamo::InsertItem: Could not insert item: {}".format(key))
        return response

    def insert_item(self, entry, retry_count=5):
        """Inserts entry item into DynamoDB table.
        Tries 5 times before raising a KeyError.

            INPUTS:
                key (dict):       Dictionary of the entry that will be deleted from the db
                                  REQUIRED
                retry_count (int): # of retries allowed if request failed
                                  REQUIRED

            OUTPUTS:
                response (dict): Dictionary of the response given from delete request

            Raises:
                KeyError : Item with specified key cannot be deleted.
        """
        for i in range(retry_count):
            response = self.table.put_item(Item=entry)
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                break
            time.sleep(1)
            print(
                "Retry #{} response returned {} - {}".format(i + 1, response['ResponseMetadata']['HTTPStatusCode'],
                                                             response))
        if response['ResponseMetadata']['HTTPStatusCode'] != 200:
            raise KeyError("AWSQA::Dynamo::InsertItem: Could not insert item: {}".format(entry))
        return response

    def get_helper_info(self):
        """This method is specifically for debugging purposes and checking
        what the attributes are.

        Prints:
            - table_name
            - region

        :return: None
        """
        print("\nDynamoDbHelper Configurations:\ntable_name {} | region {}".format(self.table_name, self.region))


class SimpleDbHelper(object):
    def __init__(self, profile="default", region="us-west-2"):
        """INPUTS:
                profile (str)     : AWS profile to use for session
                                    Default: default
                                    OPTIONAL
            OUTPUTS:
                None
        """
        boto3.setup_default_session(aws_access_key_id=current_app.config.get('AWS_ACCESS_KEY_ID'),
                                    aws_secret_access_key=current_app.config.get('AWS_SECRET_ACCESS_KEY'),
                                    region_name=region)
        # boto3.setup_default_session(profile_name=profile)
        self.sdb_client = boto3.client('sdb')

    def get_domain_metadata(self, domain_name):
        """Retrieves the domain's metadata.
        Response Syntax:
            {
                'ItemCount': 123,
                'ItemNamesSizeBytes': 123,
                'AttributeNameCount': 123,
                'AttributeNamesSizeBytes': 123,
                'AttributeValueCount': 123,
                'AttributeValuesSizeBytes': 123,
                'Timestamp': 123
            }

            INPUT:
                domain_name (str) : SimpleDB domain name
                                    REQUIRED
        """
        self._validate_input({'domain_name': domain_name}, "GetDomainMetadata")
        print('SimpleDBHelper::GetDomainMetadata: Domain {}'.format(domain_name))
        try:
            resp = self.sdb_client.domain_metadata(
                DomainName=domain_name
            )
        except ClientError as e:
            if e.response['Error']['Code'] == "NoSuchDomain":
                return None
        return resp

    def create_domain(self, domain_name):
        """Creates SimpleDB domain.
        It takes at least 10 seconds (maybe more) for AWS to create a domain.

            INPUT:
                domain_name (str) : SimpleDB domain name
                                    REQUIRED
        """
        self._validate_input({'domain_name': domain_name}, "CreateDomain")
        print('SimpleDBHelper::CreateDomain: {}'.format(domain_name))
        self.sdb_client.create_domain(
            DomainName=domain_name
        )
        time.sleep(15)

    def put_attributes(self, domain_name, item_name, attrs):
        """Put attributes into SimpleDB domain.
            INPUT:
                domain_name (str) : SimpleDB domain name
                                    REQUIRED
                item_name (str)   : Name of item.  Similar to rows on a spreadsheet. Items represent individual
                                    objects that contain one or more value-attribute pairs
                                    REQUIRED
                attrs (list)      : List of Attributes. An attribute is of format:
                                    {
                                        'Name': 'string',
                                        'Value': 'string',
                                        'Replace': True|False
                                    }
                                    REQUIRED
        """
        self._validate_input({'domain_name': domain_name,
                              'item_name': item_name,
                              'attrs': attrs}, "PutAttributes")
        print('SimpleDB::PutAttributes: Attrs {}'.format(attrs))
        self.sdb_client.put_attributes(
            DomainName=domain_name,
            ItemName=item_name,
            Attributes=attrs
        )

    def delete_attributes(self, domain_name, item_name, attrs):
        """Delete attributes from SimpleDB domain.
            INPUT:
                domain_name (str) : SimpleDB domain name
                                    REQUIRED
                item_name (str)   : Name of item.  Similar to rows on a spreadsheet. Items represent individual
                                    objects that contain one or more value-attribute pairs
                                    REQUIRED
                attrs (list)      : List of Attributes. An attribute is of format:
                                    {
                                        'Name': 'string',
                                        'Value': 'string',
                                        'Replace': True|False
                                    }
                                    REQUIRED
        """
        self._validate_input({'domain_name': domain_name,
                              'item_name': item_name,
                              'attrs': attrs}, "PutAttributes")
        print('SimpleDB::DeleteAttributes: Attrs {}'.format(attrs))
        self.sdb_client.delete_attributes(
            DomainName=domain_name,
            ItemName=item_name,
            Attributes=attrs
        )

    def batch_delete_attributes(self, domain_name, items):
        """Batch delete attributes from SimpleDB domain.
        Limits:
            - 1 MB request size
            - 25 item limit per BatchDeleteAttributes operation

            INPUT:
                domain_name (str) : SimpleDB domain name
                                    REQUIRED
                items (list)      : List of Items with Attributes. Format:
                                    [{
                                        'Name': 'string',
                                        'Attributes': [{ 'Name' : 'string', 'Value' : 'string' },]
                                    },]
                                    REQUIRED
        """
        print('SimpleDB::BatchDeleteAttributes: Items {}'.format(items))
        self.sdb_client.batch_delete_attributes(
            DomainName=domain_name,
            Items=items
        )

    def get_attributes(self, domain_name, item_name, attr_names):
        """Get attributes associated with specified item from SimpleDB domain.
            INPUT:
                domain_name (str) : SimpleDB domain name
                                    REQUIRED
                item_name (str)   : Name of item.  Similar to rows on a spreadsheet. Items represent individual
                                    objects that contain one or more value-attribute pairs
                                    REQUIRED
                attr_names (list) : List of Attribute Names
                                    REQUIRED
        """
        self._validate_input({'domain_name': domain_name,
                              'item_name': item_name,
                              'attr_names': attr_names}, "PutAttributes")
        print('SimpleDB::DeleteAttributes: Attribute Names {}'.format(attr_names))
        resp = self.sdb_client.get_attributes(
            DomainName=domain_name,
            ItemName=item_name,
            AttributeNames=attr_names,
            ConsistentRead=True
        )
        print('AWSQA::SimpleDB: Response: {}'.format(resp))
        return resp['Attributes']

    def delete_domain(self, domain_name):
        """Deletes SimpleDB domain.
        It takes at least 10 seconds (maybe more) for AWS to delete a domain.

            INPUT:
                domain_name (str) : SimpleDB domain name
                                    REQUIRED
        """
        self._validate_input({'domain_name': domain_name}, "DeleteDomain")
        print('SimpleDB::DeleteDomain: {}'.format(domain_name))
        self.sdb_client.delete_domain(
            DomainName=domain_name
        )
        time.sleep(15)

    def list_domains(self):
        """Lists all domains in SimpleDB.

        """
        resp = self.sdb_client.list_domains()
        if 'DomainNames' not in resp:
            return []
        return resp['DomainNames']

    def select(self, query):
        """Query SimpleDB Table

        :param query: (str) SQL query string
        :return: (dict) { 'Items': [ <SimpleDB_Attribute>, ...], 'NextToken': 'string' }
        """
        resp = self.sdb_client.select(
            SelectExpression=query,
            ConsistentRead=True
        )
        return resp

    def display_items(self, domains):
        """Displays all the items in each of the domains requested.
            INPUT:
                domains (list) : List of domain names
        """
        for d in domains:
            query = 'select * from `{}`'.format(d)
            resp = self.select(query)
            print('\nHere is the response for domain {}'.format(d))
            if 'Items' in resp:
                items = resp['Items']
                for i, item in enumerate(items):
                    print("="*20 + str(i) + "="*20)
                    pp.pprint(item)
                    print("="*41)
            else:
                print("Empty response")
                pprint.pprint(resp, indent=4)

    ###################
    # Private Methods #
    ###################

    def _validate_input(self, params, method):
        """Validates all the input params and makes sure that they are present.
        If not, then raise an Exception.

            INPUT:
                params (dict) : Keys are the param names and values are the input
                                REQUIRED
                method (str)  : Name of the method where input validation is happening
                                REQUIRED
        """
        for key, val in params.iteritems():
            if not val:
                raise Exception("SimpleDB::{}Error: {} cannot be None.".format(method, key))


########
# Main #
########


if __name__ == "__main__":
    # # Test ec2
    # ec2 = EC2Helper()
    # sid = "1498803195018"              # Change with your own subid
    # if ec2.pa_exist("nu-"+sid):
    #     print("YES! PA exists")
    # if ec2.dispatcher_exist("nu-"+sid):
    #     print("YES! DP exists")

    # Test CloudFormation
    build_val = 'script'


    def get_creds():
        nusess = boto3.Session(profile_name="nubeva")
        # todo remove the above line
        sts = nusess.client("sts")
        res = sts.assume_role(
            RoleArn="arn:aws:iam::504404204571:role/NubevaAuthorisationTest",
            RoleSessionName="cft_test_{}".format(build_val),
            ExternalId="setupTesting4Authorisation"
        )
        if 'Credentials' not in res:
            pprint.pprint(res)
        return res['Credentials']


    creds = get_creds()
    cfh = CloudFormationHelper(credentials=creds, region="us-west-2")
    # cfh.delete_name("TESTCFT")
    print("stack creation begin")
    succ = cfh.launch_url("https://s3-us-west-2.amazonaws.com/nchoiazure-dev-user-auth/488ad314-5e61-47c6-9caf-"
                          "f33d71bb2305.template", "TESTCFT")
    print("creation complete! waiting a bit for debugging")
    cfh.list_events("TESTCFT")
    # time.sleep(60)
    cfh.delete_name("TESTCFT")
    print("deletion complete!")
