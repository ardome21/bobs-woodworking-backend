""" Lambda function to add a product"""
import json

from auth_utils import require_role

@require_role('admin')
def lambda_handler(event, _context):
    """
    Entry point to lambda function
    """
    try:
        print("Begin Script...")
        print(f"Event body: {event['body']}")
        return {
            'statusCode': 200, 
            'body': json.dumps({'message': 'Successfully exited script'})
        }
    except Exception as e:
        print(f"Error Adding Product: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'F',
                'error': f'Internal server error: {e}'
                })
        }