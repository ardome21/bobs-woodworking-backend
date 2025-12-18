"""Lambda function to get a specific order by ID"""
import json
import boto3
from auth_utils import require_role
from dynamo_utils import normalize_dynamodb_decimals

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')

# Configuration
ORDERS_TABLE_NAME = 'bw3-orders-dev'


@require_role('user', 'admin')
def lambda_handler(event, _context):
    """Main Lambda handler for getting order by ID"""
    try:
        http_method = event.get('httpMethod') or event.get('requestContext', {}).get('http', {}).get('method')
        print(f"HTTP Method detected: {http_method}")

        if http_method != 'GET':
            return {
                'statusCode': 405,
                'body': json.dumps({'error': f'Method {http_method} Not Allowed'})
            }

        # Extract user info from JWT (injected by @require_role decorator)
        user = event.get('user', {})
        user_id = user.get('user_id')

        # Get order_id from path parameters
        path_parameters = event.get('pathParameters', {})
        order_id = path_parameters.get('order_id')

        if not order_id:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing order_id in path'})
            }

        print(f"Fetching order {order_id} for user: {user_id}")

        # Get order from DynamoDB
        orders_table = dynamodb.Table(ORDERS_TABLE_NAME)

        response = orders_table.get_item(
            Key={
                'user_id': user_id,
                'order_id': order_id
            }
        )

        if 'Item' not in response:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Order not found'})
            }

        order = response['Item']

        # Normalize Decimals for JSON serialization
        order = normalize_dynamodb_decimals(order)

        print(f"Order {order_id} found for user {user_id}")

        return {
            'statusCode': 200,
            'body': json.dumps({'order': order})
        }

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }
