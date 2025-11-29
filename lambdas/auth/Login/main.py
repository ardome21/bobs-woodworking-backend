import hashlib
import base64
import json
from datetime import datetime, timedelta, timezone
import boto3
import time
import base64
from boto3.dynamodb.conditions import Key
import jwt

dynamodb = boto3.resource('dynamodb')
userTable = dynamodb.Table('bw3-users-dev')
tokenTable = dynamodb.Table('bw3-auth-token-dev')


def check_password(password: str, stored_hash: str) -> bool:
    """Check if the provided password matches the stored hash"""
    try:
        decoded_hash_data = base64.b64decode(stored_hash.encode('utf-8'))
        salt = decoded_hash_data[:32]
        stored_pwdhash = decoded_hash_data[32:]
        computed_password_hash = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'), salt, 100000)
        return computed_password_hash == stored_pwdhash
    except Exception as e:
        print(f"Password verification error: {e}")
        raise e
    
def securely_store_server_tokens(refresh_token, user_id):
    """Store hashed refresh token with TTL (time-to-live) in DynamoDB"""
    try:
        hashed_refresh = hashlib.sha256(refresh_token.encode()).hexdigest()
        ttl = int(time.time()) + 7 * 24 * 60 * 60
        tokenTable.put_item(
            Item={
                'user_id': str(user_id),
                'refresh_token': hashed_refresh,
                'expires_at': ttl
            }
        )
        print(f"Tokens securely stored for user {user_id} with 1-week TTL")
    except Exception as e:
        print(f"Failed to securely store server tokens for user {user_id}: {e}")
        raise e
    
def create_access_token(email, user_id):
    """Create JWT access token"""
    payload = {
        'email': email,
        'user_id': user_id,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(minutes=30)
    }
    jwt_secret = boto3.client('ssm').get_parameter(Name='/bw3/jwt-secret-key', WithDecryption=True)['Parameter']['Value']
    access_token = jwt.encode(payload, jwt_secret, algorithm='HS256')
    return access_token

def login(event):
    """Login user"""
    try:
        if not event.get('body'):
            print("ERROR: No body in request")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Request body is required'})
            }
        body = json.loads(event['body']) if isinstance(
            event.get('body'), str) else event.get('body', {})

        email = body.get('email')
        password = body.get('password')
        if not email or not password:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Email and password are required'
                })
            }
        response = userTable.query(
            IndexName='email-index',
            KeyConditionExpression=Key('email').eq(email)
            )
        if not response['Items']:
            return {
                'statusCode': 401,
                'body': json.dumps({
                    'error': 'User does not exist'
                })
            }
        if len(response['Items']) > 1:
            return {
                'statusCode': 500,
                'body': json.dumps({
                    'error': 'Multiple users found'
                })
            }
        user = response['Items'][0]
        is_email_verified = user['email_verified']
        if not is_email_verified:
            return {
                'statusCode': 401,
                'body': json.dumps({
                    'error': 'Email not verified'
                })
            }
        stored_hash = user['password_hash']
        if not check_password(password,stored_hash):
            print("Password verification failed")
            return {
                'statusCode': 401,
                'body': json.dumps({
                    'error': 'Invalid credentials'
                })
            }
        user_id = user['user_id']
        access_token = create_access_token(email, user_id)
        refresh_token = base64.urlsafe_b64encode(
            boto3.client('kms').generate_random(NumberOfBytes=32)['Plaintext']
        ).decode('utf-8')
        
        securely_store_server_tokens(refresh_token, user_id)
        refresh_cookie = f'refresh_token={refresh_token}; HttpOnly; Secure; SameSite=Lax; Max-Age=604800; Path=/'

        userProfile = {
            'email': email,
            'user_id': user_id,
            'first_name': user['first_name'],
            'last_name': user['last_name']
        }
        print(f"User profile: {userProfile}")
        print(f"Access token: {access_token}")
        print(f"Refresh token: {refresh_token}")
        return {
            'statusCode': 200,
            'headers': {
                'Set-Cookie': f"{refresh_cookie}"
            },
            'body': json.dumps({
                'message': 'Login successful',
                'user': userProfile,
                'access_token': access_token,
                "expires_in": 1800
                })
            }       
    except Exception as e:
        print(f"Error logging in user: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Internal server error'
            })
        }
    
def get_auth_token(event):
    try:
        refresh_token = None
        cookies = event.get('cookies', [])
        for cookie in cookies:
            print(f"Processing cookie: {cookie}")
            if cookie.startswith('refresh_token='):
                refresh_token = cookie.split('=', 1)[1]
        return refresh_token
    except Exception as e:
        print(f"Error retrieving auth tokens from cookies: {e}")
        raise RuntimeError("Failed to retrieve auth tokens from cookies") from e

def not_authenticated_response(message='Not authenticated'):
    refresh_cookie = 'refresh_token=; Max-Age=0; HttpOnly; Secure; SameSite=Lax; Path=/'
    return {
        'statusCode': 200,
        'headers': {
            'Set-Cookie': f"{refresh_cookie}"
        },
        'body': json.dumps({
            'success': False,
            'message': message
        }),
    }

def validate_refresh_token(refresh_token):
    """
        Check if the refresh token is valid,
        Return user_id and new refresh token if valid
    """
    try:
        hashed_refresh = hashlib.sha256(refresh_token.encode()).hexdigest()
        response = tokenTable.scan(
            FilterExpression=Key('refresh_token').eq(hashed_refresh)
        )
        if not response['Items']:
            print("No matching refresh token found")
            return None, None
        if len(response['Items']) > 1:
            print("Multiple matching refresh tokens found")
            return None, None
        token_item = response['Items'][0]
        user_id = token_item['user_id']
        return user_id, refresh_token
    except Exception as e:
        print(f"Error validating and refreshing tokens: {e}")
        raise RuntimeError(f"Failed to validate refresh token: {e}") from e
    
def verify_auth(event):
    """
    Verify user authentication status
    Logic for when user opens app and we need to check if they are logged in
    1. Get refresh token from cookies
    2. Validate refresh token
    3. If valid, generate new access token and refresh token
    4. Return user data and tokens
    """
    refresh_token = get_auth_token(event)
    if not refresh_token:
        return not_authenticated_response('No refresh token provided')
    user_id, refresh_token = validate_refresh_token(refresh_token)
    
    if not user_id:
        return not_authenticated_response()
    if not refresh_token:
        return not_authenticated_response('Token validation failed')
    response = userTable.query(
        KeyConditionExpression=Key('user_id').eq(user_id)
    )

    if not response['Items']:
        return not_authenticated_response('User not found')

    if len(response['Items']) > 1:
        return not_authenticated_response('Multiple users found')
    user = response['Items'][0]
    email = user.get('email')

    access_token = create_access_token(email, user_id)
    refresh_token = base64.urlsafe_b64encode(
        boto3.client('kms').generate_random(NumberOfBytes=32)['Plaintext']
    ).decode('utf-8')
        
    securely_store_server_tokens(refresh_token, user_id)
    refresh_cookie = f'refresh_token={refresh_token}; HttpOnly; Secure; SameSite=Lax; Max-Age=604800; Path=/'

    user_profile = {
        "email": user.get("email"),
        "user_id": user.get("user_id"),
        "first_name": user.get("first_name"),
        "last_name": user.get("last_name")
    }
    return {
        'statusCode': 200,
        'headers': {
            'Set-Cookie': f"{refresh_cookie}"
        },
        'body': json.dumps({
            'success': True,
            'message': 'User already authenticated',
            'user': user_profile,
            'access_token':    access_token,
            'expires_in': 1800
        })
    }


def lambda_handler(event, _context):
    """AWS Lambda handler for user login"""
    try:
        http_method = event.get('httpMethod') or event.get(
            'requestContext', {}).get('http', {}).get('method')
        if http_method == 'OPTIONS':
            print("Handling OPTIONS preflight request")
            return
        elif http_method == 'GET':
            print("Handling GET request: Verify Auth Status")
            return verify_auth(event)
        elif http_method == 'POST':
            print("Handling POST request: User Login")
            return login(event)
        else:
            print(f"Unsupported HTTP method: {http_method}")
            return {
                'statusCode': 405,
                'body': json.dumps({'error': 'Method not allowed'})
            }
    except Exception as e:
        print(f"Lambda error: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Internal server error'
            })
        }
