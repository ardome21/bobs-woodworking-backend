"""Lambda function to create guest authentication token for checkout"""
import json
from auth_utils import create_guest_token


def validate_guest_info(body):
    """
    Validate guest information for checkout.

    Args:
        body: Request body dict

    Returns:
        Tuple of (email, first_name, last_name) or raises ValueError
    """
    email = body.get('email', '').strip()
    first_name = body.get('first_name', '').strip()
    last_name = body.get('last_name', '').strip()

    if not email:
        raise ValueError('Email is required')

    if not first_name:
        raise ValueError('First name is required')

    if not last_name:
        raise ValueError('Last name is required')

    # Basic email validation
    if '@' not in email or '.' not in email.split('@')[1]:
        raise ValueError('Invalid email format')

    return email, first_name, last_name


def lambda_handler(event, _context):
    """
    AWS Lambda handler for creating guest tokens.

    Endpoint: POST /auth/guest-token
    Body: { email, first_name, last_name }

    Returns:
        201: { access_token, expires_in, guest_profile }
        400: { error }
        405: { error }
        500: { error }
    """
    try:
        http_method = event.get('httpMethod') or event.get('requestContext', {}).get('http', {}).get('method')
        print(f"HTTP Method detected: {http_method}")

        if http_method != 'POST':
            return {
                'statusCode': 405,
                'body': json.dumps({'error': f'Method {http_method} Not Allowed'})
            }

        # Parse request body
        if isinstance(event['body'], str):
            body = json.loads(event['body'])
        else:
            body = event['body']

        # Validate guest information
        email, first_name, last_name = validate_guest_info(body)

        print(f"Creating guest token for: {email}")

        # Create guest JWT token
        access_token = create_guest_token(email, first_name, last_name)

        # Build guest profile (similar to user profile structure)
        guest_profile = {
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'role': 'guest'
        }

        return {
            'statusCode': 201,
            'body': json.dumps({
                'message': 'Guest token created successfully',
                'access_token': access_token,
                'expires_in': 3600,  # 1 hour in seconds
                'guest': guest_profile
            })
        }

    except ValueError as e:
        print(f"Validation error: {e}")
        return {
            'statusCode': 400,
            'body': json.dumps({'error': str(e)})
        }

    except KeyError as e:
        print(f"Missing required field: {e}")
        return {
            'statusCode': 400,
            'body': json.dumps({'error': f'Missing required field: {str(e)}'})
        }

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }
