"""
Lambda function to handle admin elevation confirmation from email link.
Validates the token and promotes the user to admin.
"""

import json
import os
import boto3
from boto3.dynamodb.conditions import Key
from datetime import datetime

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
USER_TABLE = os.environ.get('USER_TABLE', 'bw3-users-dev')
userTable = dynamodb.Table(USER_TABLE)

FRONTEND_URL = os.environ.get('FRONTEND_URL', 'https://bobs-woodworks.com')


def lambda_handler(event, _context):
    """
    Confirm admin elevation via email link.

    Expected query parameters:
    - userid: The user_id to promote
    - token: The elevation_token to validate
    """
    try:
        # Get query parameters
        params = event.get('queryStringParameters', {}) or {}
        user_id = params.get('userid')
        token = params.get('token')

        if not user_id or not token:
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'text/html'
                },
                'body': """
                <html>
                <head><title>Invalid Request</title></head>
                <body>
                    <h2>Invalid Request</h2>
                    <p>Missing user ID or token.</p>
                </body>
                </html>
                """
            }

        # Query user by user_id
        response = userTable.query(
            KeyConditionExpression=Key('user_id').eq(user_id)
        )

        if not response.get('Items'):
            return {
                'statusCode': 404,
                'headers': {
                    'Content-Type': 'text/html'
                },
                'body': """
                <html>
                <head><title>User Not Found</title></head>
                <body>
                    <h2>User Not Found</h2>
                    <p>The specified user does not exist.</p>
                </body>
                </html>
                """
            }

        user = response['Items'][0]

        # Check if user already has admin role
        if user.get('role') == 'admin':
            return {
                'statusCode': 302,
                'headers': {
                    'Location': f'{FRONTEND_URL}/admin-elevation-success?already_admin=true'
                },
                'body': ''
            }

        # Validate token
        stored_token = user.get('elevation_token')
        token_expires = user.get('elevation_token_expires')

        if not stored_token or stored_token != token:
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'text/html'
                },
                'body': """
                <html>
                <head><title>Invalid Token</title></head>
                <body>
                    <h2>Invalid Token</h2>
                    <p>The elevation token is invalid or has already been used.</p>
                </body>
                </html>
                """
            }

        # Check if token is expired
        if token_expires:
            expiration_time = datetime.fromisoformat(token_expires)
            if datetime.utcnow() > expiration_time:
                return {
                    'statusCode': 400,
                    'headers': {
                        'Content-Type': 'text/html'
                    },
                    'body': """
                    <html>
                    <head><title>Token Expired</title></head>
                    <body>
                        <h2>Token Expired</h2>
                        <p>This elevation request has expired. Please submit a new request.</p>
                    </body>
                    </html>
                    """
                }

        # Promote user to admin and remove elevation token
        userTable.update_item(
            Key={'user_id': user_id},
            UpdateExpression='SET #role = :role REMOVE elevation_token, elevation_token_expires',
            ExpressionAttributeNames={'#role': 'role'},
            ExpressionAttributeValues={':role': 'admin'}
        )

        user_email = user.get('email')
        user_name = f"{user.get('first_name')} {user.get('last_name')}"

        print(f"User {user_id} ({user_email}) elevated to admin via confirmation link")

        # Redirect to success page
        return {
            'statusCode': 302,
            'headers': {
                'Location': f'{FRONTEND_URL}/admin-elevation-success'
            },
            'body': ''
        }

    except Exception as e:
        print(f"Error confirming admin elevation: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'text/html'
            },
            'body': """
            <html>
            <head><title>Error</title></head>
            <body>
                <h2>Internal Server Error</h2>
                <p>An error occurred while processing your request.</p>
            </body>
            </html>
            """
        }
