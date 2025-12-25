"""
Lambda function to promote a user to admin role.
Requires admin role to execute.
"""

import json
import os
import boto3
from boto3.dynamodb.conditions import Key
from auth_utils import require_role

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
USER_TABLE = os.environ.get('USER_TABLE', 'bw3-users-dev')
userTable = dynamodb.Table(USER_TABLE)


@require_role('admin')
def lambda_handler(event, _context):
    """
    Promote a user to admin role by user_id.

    Expected body:
    {
        "user_id": "UID123"
    }
    """
    try:
        # Parse request body
        body = json.loads(event.get('body', '{}'))
        target_user_id = body.get('user_id')

        if not target_user_id:
            return {
                'statusCode': 400,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({
                    'error': 'user_id is required'
                })
            }

        # Get the requesting admin's info for logging
        requesting_admin = event.get('user', {})
        admin_email = requesting_admin.get('email', 'unknown')

        # Check if target user exists
        response = userTable.query(
            KeyConditionExpression=Key('user_id').eq(target_user_id)
        )

        if not response.get('Items'):
            return {
                'statusCode': 404,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({
                    'error': f'User {target_user_id} not found'
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
                    'error': f'User {target_user_id} is already an admin'
                })
            }

        # Update user role to admin
        userTable.update_item(
            Key={'user_id': target_user_id},
            UpdateExpression='SET #role = :role',
            ExpressionAttributeNames={'#role': 'role'},
            ExpressionAttributeValues={':role': 'admin'}
        )

        print(f"Admin {admin_email} promoted user {target_user_id} ({user.get('email')}) to admin")

        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Content-Type': 'application/json'
            },
            'body': json.dumps({
                'message': f'User {target_user_id} promoted to admin successfully',
                'user': {
                    'user_id': target_user_id,
                    'email': user.get('email'),
                    'first_name': user.get('first_name'),
                    'last_name': user.get('last_name'),
                    'role': 'admin'
                }
            })
        }

    except Exception as e:
        print(f"Error promoting user: {str(e)}")
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
