import json
import boto3
from boto3.dynamodb.conditions import Key
import jwt
from datetime import datetime, timezone

dynamodb = boto3.resource('dynamodb')
userTable = dynamodb.Table('bw3-users-dev')


def get_user_id_from_token(event):
    """Extract and verify user_id from JWT access token"""
    try:
        auth_header = event.get('headers', {}).get('Authorization') or event.get('headers', {}).get('authorization')
        if not auth_header:
            return None, {'statusCode': 401, 'body': json.dumps({'error': 'No authorization token provided'})}

        if not auth_header.startswith('Bearer '):
            return None, {'statusCode': 401, 'body': json.dumps({'error': 'Invalid authorization format'})}

        token = auth_header.split(' ')[1]
        jwt_secret = boto3.client('ssm').get_parameter(Name='/bw3/jwt-secret-key', WithDecryption=True)['Parameter']['Value']

        try:
            payload = jwt.decode(token, jwt_secret, algorithms=['HS256'])

            # Check if token is expired
            if payload.get('exp'):
                exp_timestamp = payload['exp']
                if isinstance(exp_timestamp, datetime):
                    exp_timestamp = exp_timestamp.timestamp()
                if exp_timestamp < datetime.now(timezone.utc).timestamp():
                    return None, {'statusCode': 401, 'body': json.dumps({'error': 'Token expired'})}

            user_id = payload.get('user_id')
            if not user_id:
                return None, {'statusCode': 401, 'body': json.dumps({'error': 'Invalid token payload'})}

            return user_id, None

        except jwt.ExpiredSignatureError:
            return None, {'statusCode': 401, 'body': json.dumps({'error': 'Token expired'})}
        except jwt.InvalidTokenError:
            return None, {'statusCode': 401, 'body': json.dumps({'error': 'Invalid token'})}

    except Exception as e:
        print(f"Error extracting user_id from token: {e}")
        return None, {'statusCode': 500, 'body': json.dumps({'error': 'Failed to authenticate'})}


def get_saved_addresses(event):
    """Get all saved addresses for a user"""
    try:
        user_id, error_response = get_user_id_from_token(event)
        if error_response:
            return error_response

        # Query user from DynamoDB
        response = userTable.query(
            KeyConditionExpression=Key('user_id').eq(user_id)
        )

        if not response['Items']:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'User not found'})
            }

        user = response['Items'][0]
        saved_addresses = user.get('saved_addresses', {})

        return {
            'statusCode': 200,
            'body': json.dumps({
                'addresses': saved_addresses
            })
        }

    except Exception as e:
        print(f"Error getting saved addresses: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }


def save_address(event):
    """Save a new address for a user"""
    try:
        user_id, error_response = get_user_id_from_token(event)
        if error_response:
            return error_response

        body = json.loads(event['body']) if isinstance(event.get('body'), str) else event.get('body', {})

        nickname = body.get('nickname')
        address_data = body.get('address')

        if not nickname or not address_data:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Nickname and address are required'})
            }

        # Validate address data has required fields
        required_fields = ['name', 'street', 'city', 'state', 'zip', 'country']
        for field in required_fields:
            if field not in address_data:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': f'Address missing required field: {field}'})
                }

        # Get current user
        response = userTable.query(
            KeyConditionExpression=Key('user_id').eq(user_id)
        )

        if not response['Items']:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'User not found'})
            }

        user = response['Items'][0]
        saved_addresses = user.get('saved_addresses', {})

        # Add new address
        saved_addresses[nickname] = address_data

        # Update user in DynamoDB
        userTable.update_item(
            Key={'user_id': user_id},
            UpdateExpression='SET saved_addresses = :addresses',
            ExpressionAttributeValues={
                ':addresses': saved_addresses
            }
        )

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Address saved successfully',
                'addresses': saved_addresses
            })
        }

    except Exception as e:
        print(f"Error saving address: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }


def delete_address(event):
    """Delete a saved address for a user"""
    try:
        user_id, error_response = get_user_id_from_token(event)
        if error_response:
            return error_response

        # Get nickname from path parameters
        nickname = event.get('pathParameters', {}).get('nickname')

        if not nickname:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Nickname is required'})
            }

        # Get current user
        response = userTable.query(
            KeyConditionExpression=Key('user_id').eq(user_id)
        )

        if not response['Items']:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'User not found'})
            }

        user = response['Items'][0]
        saved_addresses = user.get('saved_addresses', {})

        # Check if address exists
        if nickname not in saved_addresses:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Address not found'})
            }

        # Remove address
        del saved_addresses[nickname]

        # Update user in DynamoDB
        userTable.update_item(
            Key={'user_id': user_id},
            UpdateExpression='SET saved_addresses = :addresses',
            ExpressionAttributeValues={
                ':addresses': saved_addresses
            }
        )

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Address deleted successfully',
                'addresses': saved_addresses
            })
        }

    except Exception as e:
        print(f"Error deleting address: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }


def lambda_handler(event, _context):
    """AWS Lambda handler for saved addresses"""
    try:
        http_method = event.get('httpMethod') or event.get('requestContext', {}).get('http', {}).get('method')

        print(f"Handling {http_method} request for saved addresses")

        if http_method == 'OPTIONS':
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'OK'})
            }
        elif http_method == 'GET':
            return get_saved_addresses(event)
        elif http_method == 'POST':
            return save_address(event)
        elif http_method == 'DELETE':
            return delete_address(event)
        else:
            return {
                'statusCode': 405,
                'body': json.dumps({'error': 'Method not allowed'})
            }

    except Exception as e:
        print(f"Lambda error: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }
