""" Lambda function to add a product"""
import json

from auth_utils import require_role

@require_role('admin')
def lambda_hander(event, _context):
    """
    Entry point to lambda function
    """
    try:
        print("Begin Script...")
        print(f"Event: {event}")
    except Exception as e:
        print(f"Error verifying email: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'F',
                'error': 'Internal server error'
                })
        }