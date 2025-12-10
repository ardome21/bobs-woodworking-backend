import json
import jwt
import boto3
from functools import wraps
from datetime import datetime, timezone

# Cache the JWT secret to avoid repeated SSM calls
_jwt_secret_cache = None

def get_jwt_secret():
    """Get JWT secret from SSM with caching"""
    global _jwt_secret_cache
    if _jwt_secret_cache is None:
        ssm = boto3.client('ssm')
        _jwt_secret_cache = ssm.get_parameter(
            Name='/bw3/jwt-secret-key', 
            WithDecryption=True
        )['Parameter']['Value']
    return _jwt_secret_cache

def require_role(*allowed_roles):
    """
    Decorator to check if user has required role.
    
    Usage:
        @require_role('admin')
        def handler(event, context):
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(event, context):
            try:
                # Extract token from Authorization header
                headers = event.get('headers', {})
                # API Gateway may lowercase headers
                auth_header = headers.get('Authorization') or headers.get('authorization', '')
                
                if not auth_header.startswith('Bearer '):
                    return {
                        'statusCode': 401,
                        'headers': {
                            'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*'  # Adjust for your CORS policy
                        },
                        'body': json.dumps({
                            'message': 'Missing or invalid authorization header'
                        })
                    }
                
                # Extract token
                token = auth_header.split(' ')[1]
                
                # Verify and decode token
                jwt_secret = get_jwt_secret()
                payload = jwt.decode(token, jwt_secret, algorithms=['HS256'])
                
                # Check if token is expired (jwt.decode does this, but being explicit)
                exp = payload.get('exp')
                if exp and datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
                    return {
                        'statusCode': 401,
                        'headers': {
                            'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*'
                        },
                        'body': json.dumps({'message': 'Token has expired'})
                    }
                
                # Check role
                user_role = payload.get('role')
                if not user_role:
                    return {
                        'statusCode': 403,
                        'headers': {
                            'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*'
                        },
                        'body': json.dumps({'message': 'No role found in token'})
                    }
                
                if user_role not in allowed_roles:
                    return {
                        'statusCode': 403,
                        'headers': {
                            'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*'
                        },
                        'body': json.dumps({
                            'message': f'Insufficient permissions. Required: {", ".join(allowed_roles)}'
                        })
                    }
                
                # Add user info to event for use in handler
                event['user'] = payload
                
                # Call the actual handler
                return func(event, context)
                
            except jwt.ExpiredSignatureError:
                return {
                    'statusCode': 401,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps({'message': 'Token has expired'})
                }
            except jwt.InvalidTokenError as e:
                return {
                    'statusCode': 401,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps({'message': f'Invalid token: {str(e)}'})
                }
            except Exception as e:
                print(f"Authorization error: {str(e)}")  # CloudWatch logs
                return {
                    'statusCode': 500,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps({'message': 'Internal server error'})
                }
        
        return wrapper
    return decorator

#  LAMBDA HANDLER EXAMPLE USAGE

import json

@require_role('admin')
def lambda_handler(event, context):
    """
    This function can only be called by users with 'admin' role.
    The decorator handles all authentication and authorization.
    """
    
    # Get user info that was added by the decorator
    user = event.get('user', {})
    user_email = user.get('email')
    user_id = user.get('user_id')
    
    # Your actual business logic here
    print(f"Admin {user_email} accessed the admin endpoint")
    
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({
            'message': 'Admin operation successful',
            'user': user_email
        })
    }