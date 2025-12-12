import json

from auth_utils import require_role

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
    user_role = user.get('role')
    
    # Your actual business logic here
    print(f"Admin {user_email} accessed the admin endpoint")
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Admin operation successful',
            'user_email': user_email,
            'user_id': user_id,
            'user_role': user_role
        })
    }