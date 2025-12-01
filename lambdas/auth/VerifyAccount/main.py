"""
Lambda function to validate email address
Should upate user table and say user in confirmed
should take user to confirmation page where they can login.
"""
import boto3
import json
from boto3.dynamodb.conditions import Key

def lambda_handler(event, _context):
    try:
        query_params = event.get('queryStringParameters', {})
        if not query_params:
            print("No query params")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing confirmation parameters'})
            }
        user_id = query_params.get('userid')
        token = query_params.get('token')
        if not user_id or not token:
            print("Missing user_id or token")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid confirmation link'})
            }
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table('bw3-users-dev')
        response = table.query(
            KeyConditionExpression=Key('user_id').eq(user_id)
            )
        print(f"Response: {response}")
        user = response['Items']
        if not user:
            print("User not found")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid confirmation link'})
            }
        if len(user) > 1:
            print("Multiple users found")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid confirmation link'})
            }
        if user[0]['email_verified'] == True:
            return {
                'statusCode': 200,
                'headers': {
                    'Location': f'https://bobs-woodworks.com/confirmation-success?userid={user_id}'
                },
                'body': json.dumps({'message': 'Email already confirmed'})
            }
        if user[0]['verification_token'] != token:
            print("Invalid token")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid Token'})
            }
        table.update_item(
            Key={
                'user_id': user[0]['user_id']
            },
            UpdateExpression='SET email_verified = :val1, verification_token = :val2',
            ExpressionAttributeValues={
                ':val1': True,
                ':val2': None
            }
        )
        print("User email verified successfully")
        return {
            'statusCode': 302,
            'headers': {
                'Location': f'https://bobs-woodworks.com/confirmation-success?userid={user_id}'
            }
        }
    except Exception as e:
        print(f"Error verifying email: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f"Internal server error: {e}"})
        }
