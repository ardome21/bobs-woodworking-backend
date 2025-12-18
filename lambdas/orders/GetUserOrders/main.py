"""Lambda function to get all orders for a user"""
import json
import boto3
from boto3.dynamodb.conditions import Key
from auth_utils import require_role
from dynamo_utils import normalize_dynamodb_decimals

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')

# Configuration
ORDERS_TABLE_NAME = 'bw3-orders-dev'


@require_role('user')
def lambda_handler(event, _context):
    """Main Lambda handler for getting user orders"""
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

        print(f"Fetching orders for user: {user_id}")

        # Query orders by user_id (partition key)
        orders_table = dynamodb.Table(ORDERS_TABLE_NAME)

        response = orders_table.query(
            KeyConditionExpression=Key('user_id').eq(user_id),
            ScanIndexForward=False  # Sort by order_id descending (most recent first)
        )

        orders = response.get('Items', [])

        # Normalize Decimals for JSON serialization
        orders = normalize_dynamodb_decimals(orders)

        # Add items_count to each order for summary view
        for order in orders:
            order['items_count'] = len(order.get('items', []))

        print(f"Found {len(orders)} orders for user {user_id}")

        return {
            'statusCode': 200,
            'body': json.dumps({'orders': orders})
        }

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }
