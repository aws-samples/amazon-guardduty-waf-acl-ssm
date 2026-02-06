# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import boto3
import math
import time
import json
import logging
import os
import json
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


#======================================================================================================================
# Variables
#======================================================================================================================


FINDINGTABLE = os.environ['FINDINGTABLE']
STATES = 'states'
STATES_VALUE = 'deleted'
SNSTOPIC = os.environ['SNSTOPIC']

S3Region=os.environ['AWS_REGION']
S3BucketName=os.environ['S3BucketName']
S3OutputPrefix=os.environ['SYSTEMSMANAGEROUTPUTPREFIX']

#local_file = os.environ['object_key']
local_file = '/tmp/log'

#======================================================================================================================
# Auxiliary Functions
#======================================================================================================================

# Get file from s3
def get_s3_object(s3bucket, s3object, local_file):
    
    s3 = boto3.resource('s3')
    s3.Bucket(s3bucket).download_file(s3object,local_file)


# parse log and update malware profiles
def parse_file(local_file):
    
    ddb = boto3.resource('dynamodb')
    table = ddb.Table(FINDINGTABLE)
    
    with open(local_file, 'r') as logs:
        
        matedata = logs.readline().replace('\n', '').split(" ")
        
        n = len(matedata) - 1
        filename = get_filename_from_filepath(matedata[n])

        response = table.update_item(
            Key = {'filename':filename},
            UpdateExpression = "set permit = :p, username = :un, usergroup=:ug, size=:s, modification_date=:m_date, states=:states",
            ExpressionAttributeValues={
                    ':p': matedata[0], ':un': matedata[2], ':ug': matedata[3],  ':s': matedata[4], ':m_date': matedata[5:7], ':states': 'archived' },
        ReturnValues="ALL_NEW")
        
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            logger.info("log -- successfully update profiles %s." % filename)
            return filename


# update profile states
def update_profile_states(filename,name,value):
    
    ddb = boto3.resource('dynamodb')
    table = ddb.Table(FINDINGTABLE)
    
    response = table.update_item(
            Key = {'filename':filename},
            UpdateExpression = "set %s=:value" % (name),
            ExpressionAttributeValues={
                    ':value': value },
        ReturnValues="UPDATED_NEW")
        
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        logger.info("log -- successfully update profile  %s states %s." % (name,value))
        return True
    else:
        logger.info("log -- error updating profile  %s states %s." % (name,value))
        logger.info(response)
        return False


# query item profiles from ddb
def query_profiles(filename):
    
    ddb = boto3.resource('dynamodb')
    
    try:
        table = ddb.Table(FINDINGTABLE)
        
        response = table.get_item(Key={'filename': filename})

    except ClientError as err:
        logger.error(
            "Couldn't get item from table %s. Here's why: %s: %s",
            table.name,
            err.response['Error']['Code'], err.response['Error']['Message'])
        raise
    else:
        print('response')
        return response['Item']


# Validate and sanitize file path to prevent command injection
def validate_file_path(file_path):
    """
    Validate file path to prevent command injection attacks.
    Returns sanitized path or raises ValueError if path is invalid.
    """
    if not file_path:
        raise ValueError("File path cannot be empty")
    
    # Check for shell metacharacters that could enable command injection
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']', 
                       '<', '>', '\n', '\r', '\x00', '!', '#', '*', '?', '~']
    
    for char in dangerous_chars:
        if char in file_path:
            raise ValueError(f"Invalid character '{char}' detected in file path: {file_path}")
    
    # Validate path format - must be absolute path starting with /
    if not file_path.startswith('/'):
        raise ValueError(f"File path must be absolute (start with /): {file_path}")
    
    # Check for path traversal attempts
    if '..' in file_path:
        raise ValueError(f"Path traversal detected in file path: {file_path}")
    
    # Validate path length
    if len(file_path) > 4096:
        raise ValueError(f"File path exceeds maximum length: {len(file_path)}")
    
    return file_path


# Send command to SSM
def send_command_ssm(fullpath, instanceID):
    
    # Validate input to prevent command injection
    try:
        safe_fullpath = validate_file_path(fullpath)
    except ValueError as e:
        logger.error(f"log -- Input validation failed: {e}")
        raise
    
    # Use shlex.quote for additional shell escaping protection
    import shlex
    quoted_fullpath = shlex.quote(safe_fullpath)

    command = []
    command.append('rm -f {}'.format(quoted_fullpath))

    client = boto3.client('ssm')

    response = client.send_command(
        InstanceIds=[
            instanceID,
        ],
        DocumentName='AWS-RunShellScript',
        Parameters={
            'commands':
                command
        },
        OutputS3Region = S3Region,
        OutputS3BucketName = S3BucketName,
        OutputS3KeyPrefix = S3OutputPrefix,
    )
    return response


# get filename from filepath
def get_filename_from_filepath(filepath):
    
        filestr = filepath.split("/") 
        n = len(filestr) - 1
        filename = filestr[n]
        return filename

# Send notification to SNS topic
def handled_notify(instanceid, region, filename, findingid):

    MESSAGE = ("GuardDuty to MaliciousFile Detection Event Info:\r\n"
                 "The MaliciousFile was deleted from host" +
                 "against EC2 Instance: " + instanceid + ". The following ACL resources were targeted for update as needed: " + '\n'
                 "MaliciousFile: " + filename + '\n'
                 "Region: " + region + '\n'
                 "Finding Link: " + "https://console.aws.amazon.com/guardduty/home?region=" + region + "#/findings?macros=current&search=id%3D" + findingid
                )

    sns = boto3.client(service_name="sns")

    # Try to send the notification.
    try:

        sns.publish(
            TopicArn = SNSTOPIC,
            Message = MESSAGE,
            Subject='AWS MaliciousFile Alert'
        )
        logger.info("log -- send notification sent to SNS Topic: %s" % (SNSTOPIC))

    # Display an error if something goes wrong.
    except ClientError as e:
        logger.error('log -- error sending notification.')
        raise

#======================================================================================================================
# Lambda Entry Point
#======================================================================================================================

# Lambda handler
def lambda_handler(event, context):

    logger.info("log -- Event: %s " % json.dumps(event))
    
    try:

        s3bucket = event['detail']['bucket']['name']
        s3object = event['detail']['object']['key']

        if 'stdout' not in event['detail']['object']['key']:
            return ''
        
        # download logfile to temp dir
        get_s3_object(s3bucket, s3object, local_file)
        
        # parse logfile update matedata to ddb
        filename = parse_file(local_file)

        # get item bean
        item = query_profiles(filename)

        # delete malware file
        response = send_command_ssm(item['filePath'],item['instanceID'])

        # update malware states in ddb and send SNS
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            update_profile_states(filename, STATES, STATES_VALUE)
            handled_notify(item['instanceID'],item['Region'],item['filename'],item['findingID'])

    except Exception as e:
        logger.error('log -- something went wrong.')
        raise
