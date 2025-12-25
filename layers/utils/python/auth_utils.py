"""
Authentication utilities for Lambda functions.
Provides decorators for JWT validation and role-based access control.
"""
import json
import jwt
import boto3
from functools import wraps
from datetime import datetime, timedelta, timezone

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


def create_guest_token(email, first_name, last_name):
    """
    Create JWT token for guest checkout.

    Args:
        email: Guest's email address
        first_name: Guest's first name
        last_name: Guest's last name

    Returns:
        JWT access token with guest role
    """
    payload = {
        'email': email,
        'first_name': first_name,
        'last_name': last_name,
        'user_id': f'GUEST-{email}',  # Temporary ID for guest
        'role': 'guest',
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(hours=1)  # 1 hour expiry for checkout
    }
    jwt_secret = get_jwt_secret()
    access_token = jwt.encode(payload, jwt_secret, algorithm='HS256')
    return access_token

def require_role(*allowed_roles):
    """
    Decorator to check if user has required role.
    Validates JWT token from Authorization header and checks user role.

    Usage:
        @require_role('admin')
        def handler(event, context):
            # event['user'] contains the decoded JWT payload
            user = event.get('user', {})
            user_id = user.get('user_id')
            ...

        @require_role('user', 'admin', 'guest')
        def handler(event, context):
            # Allows users, admins, and guests (for checkout)
            ...

    Args:
        *allowed_roles: Variable number of role strings ('user', 'admin', 'guest').
                       If no roles provided, only validates that a valid JWT exists.

    Returns:
        Decorator function that wraps the actual handler.
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
                        'body': json.dumps({'message': 'Token has expired'})
                    }
                
                # Check role if specific roles are required
                if allowed_roles:
                    user_role = payload.get('role')
                    if not user_role:
                        return {
                            'statusCode': 403,
                            'body': json.dumps({'message': 'No role found in token'})
                        }

                    if user_role not in allowed_roles:
                        return {
                            'statusCode': 403,
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
                    'body': json.dumps({'message': 'Token has expired'})
                }
            except jwt.InvalidTokenError as e:
                return {
                    'statusCode': 401,
                    'body': json.dumps({'message': f'Invalid token: {str(e)}'})
                }
            except Exception as e:
                print(f"Authorization error: {str(e)}")  # CloudWatch logs
                return {
                    'statusCode': 500,
                    'body': json.dumps({'message': 'Internal server error'})
                }
        
        return wrapper
    return decorator
