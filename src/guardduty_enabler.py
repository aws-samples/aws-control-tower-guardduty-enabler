""" 
Copyright 2020 Amazon.com, Inc. or its affiliates.
All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License").
You may not use this file except in compliance with the License.
A copy of the License is located at
   http://aws.amazon.com/apache2.0/
or in the "license" file accompanying this file.

This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

This script orchestrates the enablement and centralization of GuardDuty
across an enterprise of AWS accounts. It takes in a list of AWS Account
Numbers, iterates through each account and region to enable GuardDuty.
It creates each account as a Member in the GuardDuty Admin account.
It invites and accepts the invite for each Member account.
"""

import boto3
import json
import os
import time
import logging
import urllib3
from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
if 'log_level' in os.environ:
    LOGGER.setLevel(os.environ['log_level'])
    LOGGER.info("Log level set to %s" % LOGGER.getEffectiveLevel())
else:
    LOGGER.setLevel(logging.ERROR)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)

session = boto3.Session()


def send(
  event, context, responseStatus, responseData,
  physicalResourceId=None, noEcho=False):
    response_url = event['ResponseURL']
    print(response_url)
    ls = context.log_stream_name
    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = 'See the details in CloudWatch Log Stream: ' + ls
    responseBody['PhysicalResourceId'] = physicalResourceId or ls
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = noEcho
    responseBody['Data'] = responseData
    json_response_body = json.dumps(responseBody)
    print("Response body:\n" + json_response_body)
    headers = {
        'content-type': '',
        'content-length': str(len(json_response_body))
    }
    http = urllib3.PoolManager()
    try:
        response = http.request('PUT',
                                response_url,
                                body=json_response_body,
                                headers=headers)
        print("Status code: " + response.reason)
    except Exception as e:
        print("send(..) failed executing requests.put(..): " + str(e))


def get_enabled_regions(session, regions):
    """
    With the introduction of regions that can be disabled it is necessary
    to test to see if a region can be used and not just assume we can
    enable it.
    """
    enabled_regions = []
    for region in regions:
        sts_client = session.client('sts', region_name=region)
        try:
            sts_client.get_caller_identity()
            enabled_regions.append(region)
        except ClientError as e:
            if e.response['Error']['Code'] == "InvalidClientTokenId":
                LOGGER.debug(f"{region} region is disabled.")
            else:
                LOGGER.debug(f"Error {e.response['Error']} occured "
                             f"testing region {region}")
    return enabled_regions


def get_account_list():
    """
    Gets a list of Active AWS Accounts in the Organization.
    This is called if the function is not executed by an Sns trigger
    and is used for periodic scheduling to ensure all accounts are
    correctly configured, and prevent gaps in security from activities
    like new regions being added or GuardDuty being disabled.
    """
    aws_account_dict = dict()
    orgclient = session.client('organizations', region_name=session.region_name)
    accounts = orgclient.list_accounts()
    while 'NextToken' in accounts:
        moreaccounts = orgclient.list_accounts(NextToken=accounts['NextToken'])
        for acct in accounts['Accounts']:
            moreaccounts['Accounts'].append(acct)
        accounts = moreaccounts
    LOGGER.debug(accounts)
    for account in accounts['Accounts']:
        LOGGER.debug(account)
        # Filter out suspended accounts and save valid accounts in a dict
        if account['Status'] == 'ACTIVE':
            accountid = account['Id']
            email = account['Email']
            aws_account_dict.update({accountid: email})
    return aws_account_dict


def assume_role(aws_account_number, role_name):
    """
    Assumes the provided role in each account and returns a GuardDuty client
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :param aws_region:
        AWS Region for the Client call, not required for IAM calls
    :return: GuardDuty client in the specified AWS Account and Region
    """
    # Beginning the assume role process for account
    sts_client = boto3.client('sts')
    # Get the current partition
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]
    response = sts_client.assume_role(
        RoleArn=f'arn:{partition}:iam::{aws_account_number}:role/{role_name}',
        RoleSessionName='EnableGuardDuty'
    )
    # Storing STS credentials
    sts_session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )
    LOGGER.debug(f"Assumed session for {aws_account_number}.")
    return sts_session


def get_admin_members(admin_session, aws_region, detector_id):
    """
    Returns a list of current members of the GuardDuty admin account
    :param aws_region: AWS Region of the GuardDuty admin account
    :param detector_id:
        DetectorId of the GuardDuty admin account in the AWS Region
    :return: dict of AwsAccountId:RelationshipStatus
    """
    member_dict = dict()
    gd_client = admin_session.client('guardduty', region_name=aws_region)
    paginator = gd_client.get_paginator('list_members')
    operation_parameters = {
        'DetectorId': detector_id,
        'OnlyAssociated': 'false'
    }
    # Need to paginate and iterate over results
    page_iterator = paginator.paginate(**operation_parameters)
    for page in page_iterator:
        if page['Members']:
            for member in page['Members']:
                member_dict.update(
                    {member['AccountId']: member['RelationshipStatus']}
                )
    return member_dict


def list_detectors(client, aws_region):
    """
    Lists the detectors in a given Account/Region
    Used to detect if a detector exists already
    :param client: GuardDuty client
    :param aws_region: AWS Region
    :return: Dictionary of AWS_Region: DetectorId
    """
    detector_dict = client.list_detectors()
    if detector_dict['DetectorIds']:
        for detector in detector_dict['DetectorIds']:
            detector_dict.update({aws_region: detector})
    else:
        detector_dict.update({aws_region: ''})
    return detector_dict


def logStatus(action, account, admin, region, status):
    """
    Log status of each member account
    :param action: action on the account, such as Removing or Disassociating
    :param account: GuardDuty member account
    :parm admin: GuardDuty admin account
    :param aws_region: AWS Region
    :param: GuardDuty member account status
    """
    LOGGER.info(f"{action} account {account} from GuardDuty admin {admin} "
                f" in region {region} because of it is {status}")


def get_ct_regions(session):
    # This is a hack to find the control tower supported regions, as there
    # is no API for it right now it enumerates the
    # AWSControlTowerBP-BASELINE-CLOUDWATCH CloudFormation StackSet and finds
    # what regions it has deployed stacks too.
    # It doesn't have to evaluate enabled_regions as only enabled regions
    # will/can have stacks deployed
    cf = session.client('cloudformation')
    stacks = cf.list_stack_instances(
        StackSetName='AWSControlTowerBP-BASELINE-CLOUDWATCH')
    region_set = set()
    for stack in stacks['Summaries']:
        region_set.add(stack['Region'])
    return list(region_set)


def list_members(client, detector_id):
    member_dict = dict()
    response = client.list_members(
        DetectorId=detector_id,
        OnlyAssociated='false'
    )
    for member in response['Members']:
        member_dict.update({member['AccountId']: member['RelationshipStatus']})
    return member_dict


def disable_guardduty(admin_session, guardduty_regions, admin_account):
    for aws_region in guardduty_regions:
        gd_client = admin_session.client('guardduty', region_name=aws_region)
        detector_dict = list_detectors(gd_client, aws_region)
        detector_id = detector_dict[aws_region]
        if detector_id != '':
            LOGGER.info(f"GuardDuty is active in {aws_region}")
        if detector_id != '':
            member_dict = list_members(gd_client, detector_id)
            if member_dict:
                LOGGER.info(f"There are members in {aws_region}.")
                response = gd_client.disassociate_members(
                    AccountIds=list(member_dict.keys()),
                    DetectorId=detector_id
                )
                response = gd_client.delete_members(
                    DetectorId=detector_id,
                    AccountIds=list(member_dict.keys())
                )
                LOGGER.info(f"Deleting members for {admin_account} "
                            f"in {aws_region}")
        else:
            LOGGER.info(f"No detector found for {admin_account} "
                        f"in {aws_region}")


def lambda_handler(event, context):
    LOGGER.debug('REQUEST RECEIVED:\n %s', event)
    LOGGER.debug('REQUEST RECEIVED:\n %s', context)
    guardduty_regions = []
    admin_account = os.environ['admin_account']
    admin_session = assume_role(
        admin_account,
        os.environ['assume_role']
    )
    if os.environ['region_filter'] == 'GuardDuty':
        guardduty_regions = get_enabled_regions(
            session, session.get_available_regions('guardduty',partition_name=os.environ['topic'].split(":")[1]))
        LOGGER.debug(f"Enabling members in all available GuardDuty "
                     f"regions {guardduty_regions}")
    else:
        guardduty_regions = get_ct_regions(session)
        LOGGER.debug(f"Enabling members in all available ControlTower "
                     f"regions {guardduty_regions}")
    # Check for Custom Resource Call
    if 'RequestType' in event and (
            event['RequestType'] == "Delete" or
            event['RequestType'] == "Create" or
            event['RequestType'] == "Update"):
        action = event['RequestType']
        if action == "Delete":
            disable_guardduty(
                admin_session,
                guardduty_regions,
                admin_account
    )
            LOGGER.info("Sending Custom Resource Response")
            responseData = {}
            send(event, context, "SUCCESS", responseData)
        if action == "Delete":
            # Exit on delete so it doesn't re-enable existing accounts
            raise SystemExit()
        else:
            LOGGER.info("Sending Custom Resource Response")
            responseData = {}
            send(event, context, "SUCCESS", responseData)
    admin_detector_id_dict = dict()
    aws_account_dict = dict()
    # detect if the function was called by Sns
    if 'Records' in event:
        message = event['Records'][0]['Sns']['Message']
        LOGGER.debug(message)
        jsonmessage = json.loads(message)
        accountid = jsonmessage['AccountId']
        email = jsonmessage['Email']
        aws_account_dict.update({accountid: email})
    else:
        # Not called by Sns so enumerating accounts, and recursively
        # calling itself via sns
        aws_account_dict = get_account_list()
        sns_client = session.client(
            'sns',
            region_name=os.environ['AWS_REGION']
        )
        for accountid, email in aws_account_dict.items():
            # sns is used to fan out the requests, as too many accounts
            # would result in the function timing out
            LOGGER.debug(f"Sending job to configure account {accountid}")
            response = sns_client.publish(
                TopicArn=os.environ['topic'],
                Message="{\"AccountId\":\""+accountid+"\","
                "\"Email\":\""+email+"\"}"
            )
        return True
    for aws_region in guardduty_regions:
        gd_client = admin_session.client('guardduty', region_name=aws_region)
        detector_dict = list_detectors(gd_client, aws_region)
        if detector_dict[aws_region]:
            LOGGER.debug(f"Found existing detector {detector_dict[aws_region]}"
                         f" in {aws_region} for {admin_account}")
            admin_detector_id_dict.update(
                {aws_region: detector_dict[aws_region]}
            )
        else:
            detector_str = gd_client.create_detector(Enable=True)['DetectorId']
            LOGGER.info(f"Created detector {detector_str} in {aws_region} "
                        f"for {admin_account}")
            admin_detector_id_dict.update({aws_region: detector_str})
    failed_accounts = []
    for account in aws_account_dict.keys():
        if account != os.environ['ct_root_account']:
            target_session = assume_role(account, os.environ['assume_role'])
        else:
            target_session = session
        for aws_region in guardduty_regions:
            LOGGER.debug(f"Beginning {account} in {aws_region}")
            gd_client = target_session.client(
                'guardduty',
                region_name=aws_region
            )
            detector_dict = list_detectors(gd_client, aws_region)
            detector_id = detector_dict[aws_region]
            if detector_id:
                LOGGER.debug(f"Found existing detector {detector_id} in "
                             f"{aws_region} for {account}")
                try:
                    detector_status = gd_client.get_detector(
                        DetectorId=detector_id
                    )
                    if detector_status['Status'] != 'ENABLED':
                        update_result = gd_client.update_detector(
                            DetectorId=detector_id,
                            Enable=True,
                            FindingPublishingFrequency=(
                                detector_status['FindingPublishingFrequency']
                            )
                        )
                        LOGGER.warning(f"Re-enabled disabled detector "
                                       f"{detector_id} in {aws_region} for "
                                       f"{account} with {update_result}")
                except ClientError as e:
                    LOGGER.debug(f"Error Processing Account {account}")
                    failed_accounts.append({
                        'AccountId': account, 'Region': aws_region
                    })
            else:
                detector_str = \
                    gd_client.create_detector(Enable=True)['DetectorId']
                LOGGER.info(f"Created detector {detector_str} in "
                            f"{aws_region} for {account}")
                detector_id = detector_str
            admin_detector_id = admin_detector_id_dict[aws_region]
            member_dict = get_admin_members(
                admin_session,
                aws_region,
                admin_detector_id
            )
            if ((account not in member_dict) and
                    (account != admin_account)):
                gd_client = admin_session.client(
                    'guardduty',
                    region_name=aws_region
                )
                gd_client.create_members(
                    AccountDetails=[
                        {
                            'AccountId': account,
                            'Email': aws_account_dict[account]
                        }
                    ],
                    DetectorId=admin_detector_id
                )
                LOGGER.info(f"Added Account {account} to member list "
                            f"in GuardDuty admin account {admin_account} "
                            f"for region {aws_region}")
                start_time = int(time.time())
                while account not in member_dict:
                    if (int(time.time()) - start_time) > 300:
                        LOGGER.debug(f"Membership did not show up for "
                                     f"account {account}, skipping")
                        break
                    time.sleep(5)
                    member_dict = get_admin_members(
                        admin_session,
                        aws_region,
                        admin_detector_id
                    )
            else:
                LOGGER.debug(f"Account {account} is already a member of "
                             f"{admin_account} in region {aws_region}")
            if account != admin_account:
                if member_dict[account] == 'Enabled':
                    LOGGER.debug(f"Account {account} is already "
                                 f"{member_dict[account]}")
                else:
                    admin_gd_client = admin_session.client(
                        'guardduty',
                        region_name=aws_region
                    )
                    gd_client = target_session.client(
                        'guardduty',
                        region_name=aws_region
                    )
                    start_time = int(time.time())
                    member_dict = get_admin_members(
                        admin_session,
                        aws_region,
                        admin_detector_id
                    )
                    while (account not in member_dict) or (member_dict[account] != 'Enabled'):
                        if (int(time.time()) - start_time) > 300:
                            LOGGER.debug(f"Enabled status did not show up "
                                         f"for account {account}, skipping")
                            break
                        if account not in member_dict:
                            member_dict[account] = "missing"
                        if (account in member_dict) and (member_dict[account] == 'Created'):
                            admin_gd_client = admin_session.client(
                                'guardduty', region_name=aws_region
                            )
                            admin_gd_client.invite_members(
                                AccountIds=[account],
                                DetectorId=admin_detector_id,
                                DisableEmailNotification=True
                            )
                            LOGGER.info(f"Invited Account {account} to "
                                        f"GuardDuty admin account "
                                        f"{admin_account} in "
                                        f"region {aws_region}")
                        elif (account in member_dict) and (member_dict[account] == 'Invited'):
                            response = gd_client.list_invitations()
                            invitation_id = None
                            for invitation in response['Invitations']:
                                invitation_id = invitation['InvitationId']
                            if invitation_id is not None:
                                gd_client.accept_invitation(
                                    DetectorId=detector_id,
                                    InvitationId=invitation_id,
                                    MasterId=str(admin_account)
                                )
                                LOGGER.info(f"Accepting Account {account} to "
                                            f"GuardDuty admin account "
                                            f"{admin_account} in "
                                            f"region {aws_region}")
                        elif (account in member_dict) and (member_dict[account] == 'Resigned'):
                            response = admin_gd_client.delete_members(
                                DetectorId=admin_detector_id,
                                AccountIds=[account]
                            )
                            logStatus(
                                "Removing",
                                account,
                                admin_account,
                                aws_region,
                                member_dict[account]
                            )
                        elif (account in member_dict) and (member_dict[account] == 'Disabled'):
                            response = admin_gd_client.disassociate_members(
                                DetectorId=admin_detector_id,
                                AccountIds=[account]
                            )
                            logStatus(
                                "Disassociating",
                                account,
                                admin_account,
                                aws_region,
                                member_dict[account]
                            )
                        elif (account in member_dict) and (member_dict[account] == 'Removed'):
                            response = admin_gd_client.delete_members(
                                DetectorId=admin_detector_id,
                                AccountIds=[account]
                            )
                            logStatus(
                                "Removing",
                                account,
                                admin_account,
                                aws_region,
                                member_dict[account]
                            )
                        else:
                            logStatus(
                                "Waiting",
                                account,
                                admin_account,
                                aws_region,
                                member_dict[account]
                            )
                        time.sleep(5)
                        member_dict = get_admin_members(
                            admin_session,
                            aws_region,
                            admin_detector_id
                        )
                    LOGGER.debug(f"Finished {account} in {aws_region}")

    if len(failed_accounts) > 0:
        LOGGER.info("Error Processing following accounts: %s" % (
            json.dumps(failed_accounts, sort_keys=True, default=str)))
