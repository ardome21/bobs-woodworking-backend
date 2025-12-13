# """ Lambda function to add a product"""
import json
from auth_utils import require_rolex

def add_product(event):
    """
    Business logic to add a product.
    """
    try:
        print("Starting add_product function")
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Product added successfully'
            })
        }
        
    except Exception as e:
        print(f"Error in add_product: {e}")
        raise RuntimeError(f"Failed to add product: {e}") from e

@require_role('admin')
def lambda_handler(event, _context):
    """
    Entry point to lambda function
    """
    print(f"Lambda handler started with event: {json.dumps(event, default=str)}")
    try:
        http_method = event.get('httpMethod') or event.get(
            'requestContext', {}).get('http', {}).get('method')
        print(f"HTTP Method: {http_method}")
        
        if http_method == 'OPTIONS':
            print("Handling OPTIONS preflight request")
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'OK'})
            }
        if http_method == 'POST': 
            print("Handling POST request")
            return add_product(event)
        else:
            print(f"Unsupported HTTP method: {http_method}")
            return {
                'statusCode': 405,
                'body': json.dumps({'message': 'Method Not Allowed'})
            }
    except RuntimeError as re:
        print(f"Runtime Error Adding Product: {re}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Failed to add product',
                'error': str(re)
                })
        }
    except Exception as e:
        print(f"Error Adding Product: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Internal server error',
                'error': str(e)
                })
        }