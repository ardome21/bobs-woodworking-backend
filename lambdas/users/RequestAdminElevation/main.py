"""
Lambda function for users to request admin elevation.
Sends an email to admins with a confirmation link.
"""

import json
import os
import uuid
import boto3
from boto3.dynamodb.conditions import Key
from datetime import datetime, timedelta
from auth_utils import require_role

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
ses = boto3.client('ses', region_name='us-east-1')

USER_TABLE = os.environ.get('USER_TABLE', 'bw3-users-dev')
userTable = dynamodb.Table(USER_TABLE)

ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@bobs-woodworks.com')
SENDER_EMAIL = 'noreply@bobs-woodworks.com'


def send_admin_elevation_email(user_email, user_first_name, user_last_name, user_id, elevation_token):
    """Send admin elevation request email to admin"""
    subject = "Admin Elevation Request - Bob's Woodworking"

    confirmation_link = f"https://api.bobs-woodworks.com/confirm-admin-elevation?userid={user_id}&token={elevation_token}"

    html_body = f"""
    <html>
    <head></head>
    <body>
        <h2>Admin Elevation Request</h2>
        <p>A user has requested admin privileges for Bob's Woodworking:</p>
        <ul>
            <li><strong>Name:</strong> {user_first_name} {user_last_name}</li>
            <li><strong>Email:</strong> {user_email}</li>
            <li><strong>User ID:</strong> {user_id}</li>
        </ul>
        <p>To approve this request and grant admin access, click the link below:</p>
        <p>
            <a href="{confirmation_link}"
               style="background-color: #4CAF50; color: white; padding: 14px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">
                Approve Admin Access
            </a>
        </p>
        <p>Or copy and paste this link in your browser:</p>
        <p>{confirmation_link}</p>
        <p><strong>Note:</strong> This link will expire in 24 hours.</p>
        <p>If you did not expect this request or want to deny it, simply ignore this email.</p>
        <br>
        <p>Bob's Woodworking</p>
    </body>
    </html>
    """

    text_body = f"""
Admin Elevation Request

A user has requested admin privileges for Bob's Woodworking:

Name: {user_first_name} {user_last_name}
Email: {user_email}
User ID: {user_id}

To approve this request and grant admin access, visit:
{confirmation_link}

Note: This link will expire in 24 hours.

If you did not expect this request or want to deny it, simply ignore this email.

Bob's Woodworking
    """

    try:
        response = ses.send_email(
            Source=SENDER_EMAIL,
            Destination={'ToAddresses': [ADMIN_EMAIL]},
            Message={
                'Subject': {'Data': subject},
                'Body': {
                    'Text': {'Data': text_body},
                    'Html': {'Data': html_body}
                }
            }
        )
        print(f"Admin elevation email sent. MessageId: {response['MessageId']}")
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False


@require_role('user', 'admin')
def lambda_handler(event, _context):
    """
    Request admin elevation for the authenticated user.
    Sends email to admin with confirmation link.
    """
    try:
        # Get the requesting user's info from JWT
        user_data = event.get('user', {})
        user_id = user_data.get('user_id')
        user_email = user_data.get('email')

        if not user_id or not user_email:
            return {
                'statusCode': 401,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({
                    'error': 'User not authenticated'
                })
            }

        # Get full user details from database
        response = userTable.query(
            KeyConditionExpression=Key('user_id').eq(user_id)
        )

        if not response.get('Items'):
            return {
                'statusCode': 404,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({
                    'error': 'User not found'
                })
            }

        user = response['Items'][0]

        # Check if user is already an admin
        if user.get('role') == 'admin':
            return {
                'statusCode': 400,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({
                    'error': 'You are already an admin'
                })
            }

        # Generate elevation token (UUID)
        elevation_token = str(uuid.uuid4())

        # Calculate expiration (24 hours from now)
        expiration = datetime.utcnow() + timedelta(hours=24)

        # Store elevation token in user record
        userTable.update_item(
            Key={'user_id': user_id},
            UpdateExpression='SET elevation_token = :token, elevation_token_expires = :expires',
            ExpressionAttributeValues={
                ':token': elevation_token,
                ':expires': expiration.isoformat()
            }
        )

        # Send email to admin
        email_sent = send_admin_elevation_email(
            user_email=user.get('email'),
            user_first_name=user.get('first_name'),
            user_last_name=user.get('last_name'),
            user_id=user_id,
            elevation_token=elevation_token
        )

        if not email_sent:
            return {
                'statusCode': 500,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({
                    'error': 'Failed to send admin elevation request email'
                })
            }

        print(f"Admin elevation requested by user {user_id} ({user_email})")

        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Content-Type': 'application/json'
            },
            'body': json.dumps({
                'message': 'Admin elevation request sent successfully. An administrator will review your request.'
            })
        }

    except Exception as e:
        print(f"Error requesting admin elevation: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Content-Type': 'application/json'
            },
            'body': json.dumps({
                'error': 'Internal server error'
            })
        }
