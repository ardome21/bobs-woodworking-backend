import json
import hashlib
import os
import base64
import re
import boto3
from datetime import datetime, timezone
from boto3.dynamodb.conditions import Key
import uuid

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('bw3-users-dev')

def hash_password(password: str) -> str:
    """Hash a password using PBKDF2 with SHA256"""
    salt = os.urandom(32)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    combined = salt + pwdhash
    return base64.b64encode(combined).decode('utf-8')

def generate_user_id():
    response = users_table.scan(ProjectionExpression='user_id')
    
    max_id = 0
    for item in response['Items']:
        user_id = item['user_id']
        if user_id.startswith('UID'):
            try:
                num = int(user_id[3:])
                max_id = max(max_id, num)
            except ValueError:
                continue
    
    return f"UID{max_id + 1:03d}"

def create_user_record(email: str, firstName: str, lastName: str, hashed_password: str, verification_token: str, user_id: str):
    """Create user record in database"""
    timestamp = datetime.now(timezone.utc) .isoformat()
    
    user_item = {
        'user_id': user_id,
        'email': email,
        'first_name': firstName,
        'last_name': lastName,
        'password_hash': hashed_password,
        'created_at': timestamp,
        'updated_at': timestamp,
        'is_active': True,
        'email_verified': False,
        'verification_token': verification_token
    }
    
    try:
        users_table.put_item(Item=user_item)
    except Exception as e:
        print(f"Error creating user: {str(e)}")
        raise

def validate_email(email: str) -> bool:
    """Validate email format"""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, email) is not None

def check_user_exists(email: str) -> bool:
    """Check if user already exists using GSI on email"""
    try:
        response = users_table.query(
            IndexName='email-index',
            KeyConditionExpression=Key('email').eq(email),
            Select='COUNT'
        )
        return response['Count'] > 0
    except Exception as e:
        print(f"Error checking user existence: {e}")
        raise e

def send_email(user_email: str, user_first_name: str, user_last_name: str, user_id: str, verification_token: str):
    """Send end email using SES"""
    ses = boto3.client('ses', region_name='us-east-1')
    sender_email = 'noreply@bobs-woodworks.com'
    admin_email = 'ardome21+aws@gmail.com'
    subject = "Confirm Email for Bob's Woodworking App"
    confirmation_link = f"https://api.bobs-woodworks.com/verify-account?userid={user_id}&token={verification_token}" # TODO: Update with new api

    body = f"""
    <html>
    <body>
        <h1>Welcome to Bob's Woodworking App, {user_first_name} {user_last_name}!</h1>
        <p>Thank you for joining Bob's Woodworking App. We're excited to have you on board.</p>
        <p>Please click the link to confirm this email and user</p>
        <a href="{confirmation_link}">
        <p>Best regards,<br>Bob's Woodworking App Team</p>
    </body>
    </html>
    """
    
    try:
        if user_email != admin_email:
            ses.send_email(
                Source=sender_email,
                Destination={'ToAddresses': [admin_email]},
                Message={
                    'Subject': {'Data': 'Admin: ' + subject},
                    'Body': {'Html': {'Data': body}}
                }
            )
            print(f"Admin email sent to {admin_email}") 
            return True
        else: 
            ses.send_email(
                Source=sender_email,
                Destination={'ToAddresses': [user_email]},
                Message={
                    'Subject': {'Data': subject},
                    'Body': {'Html': {'Data': body}}
                }
            )
            print(f"End user email sent to {user_email}")
            return False
    except Exception as e:
        print(f"Error sending end email: {str(e)}")
        raise e

def lambda_handler(event, _context):
    """Main Lambda handler for creating users"""
    try:
        http_method = event.get('httpMethod') or event.get('requestContext', {}).get('http', {}).get('method')
        print(f"HTTP Method detected: {http_method}")
        
        if http_method == 'OPTIONS':
            print("Handling OPTIONS preflight request")
            return
        if http_method != 'POST':
            print(f"Unsupported HTTP method: {http_method}")
            return {
                'statusCode': 405,
                'body': json.dumps({
                    'error': f'Method {http_method} Not Allowed'
                })
            }
        print("Handling POST request")

        if isinstance(event['body'], str):
            body = json.loads(event['body'])
        else:
            body = event['body']
        
        required_fields = ['email', 'password', 'first_name', 'last_name']
        missing_fields = [field for field in required_fields if field not in body or not body[field]]
        
        if missing_fields:
            print(f"Missing required fields: {', '.join(missing_fields)}")
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': f'Missing required fields: {", ".join(missing_fields)}'
                })
            }
        
        email = body['email'].lower().strip()
        password = body['password']
        firstName = body['first_name'].strip()
        lastName = body['last_name'].strip()
        
        print(f"Email: {email}, First Name: {firstName}, Last Name: {lastName}")
        
        if not validate_email(email):
            print(f"Invalid email format: {email}")
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Invalid email format'
                })
            }
        
        if len(password) < 6:
            print(f"Password too short: {password}")
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Password must be at least 8 characters long'
                    })
            }
        
        if check_user_exists(email):
            print(f"User already exists: {email}")
            return {
                'statusCode': 409,
                'body': json.dumps({
                    'error': 'User with this email already exists'
                    })
            }
        
        hashed_password = hash_password(password)
        verification_token = str(uuid.uuid4())
        user_id = generate_user_id()
        
        create_user_record(
            email=email,
            firstName=firstName,
            lastName=lastName,
            hashed_password=hashed_password,
            verification_token=verification_token,
            user_id=user_id
        )
        print(f"User created successfully: {email}")
        send_admin_email = send_email(email, firstName, lastName, user_id, verification_token)
        
        if send_admin_email:
            return {
                'statusCode': 202,
                'body': json.dumps({
                    'message': 'User created successfully, Admin Email sent',
                    'user': {
                        'email': email,
                        'user_id': user_id,
                        'firstName': firstName,
                        'lastName': lastName
                    }
                })
            }
        return {
            'statusCode': 201,
            'body': json.dumps({
                'message': 'User created successfully: User Email Sen',
                'user': {
                    'email': email,
                    'user_id': user_id,
                    'firstName': firstName,
                    'lastName': lastName
                }
            })
        }
    
    except json.JSONDecodeError:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': 'Invalid JSON format'
            })
        }
    
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Internal server error'
            })
        }