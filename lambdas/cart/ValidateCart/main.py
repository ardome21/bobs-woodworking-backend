"""Lambda function to validate cart items and return fresh product data with new presigned URLs"""
import json
import boto3
from typing import List, Dict, Any
from s3_utils import generate_presigned_url

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')

# Configuration
PRODUCTS_TABLE_NAME = 'bw3-products-dev'
S3_BUCKET_NAME = 'bw3-images-dev'


def get_products_by_ids(product_ids: List[str]) -> Dict[str, Any]:
    """
    Fetch multiple products from DynamoDB by their IDs.

    Args:
        product_ids: List of product IDs to fetch

    Returns:
        Dict mapping product_id to product data
    """
    products_table = dynamodb.Table(PRODUCTS_TABLE_NAME)
    products = {}

    for product_id in product_ids:
        try:
            response = products_table.get_item(Key={'product_id': str(product_id)})

            if 'Item' in response:
                products[str(product_id)] = response['Item']

        except Exception as e:
            print(f"Error fetching product {product_id}: {e}")
            # Continue with other products even if one fails

    return products


def format_cart_item(product_id: str, requested_quantity: int, product_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format a cart item with fresh presigned URLs and available quantity.

    Args:
        product_id: Product ID
        requested_quantity: Quantity requested in cart
        product_data: Product data from DynamoDB

    Returns:
        Formatted cart item with updated data
    """
    # Generate fresh presigned URLs for images
    image_urls = []
    for s3_key in product_data.get('images', []):
        if isinstance(s3_key, str):
            image_urls.append(generate_presigned_url(S3_BUCKET_NAME, s3_key))

    available_quantity = int(product_data.get('quantity', 0))

    # Adjust quantity if not enough stock
    adjusted_quantity = min(requested_quantity, available_quantity)

    return {
        'product_id': int(product_id),
        'product_name': product_data.get('title', ''),
        'unit_price': float(product_data.get('price', 0)),
        'quantity': adjusted_quantity,
        'requested_quantity': requested_quantity,
        'available_quantity': available_quantity,
        'imageUrl': image_urls[0] if image_urls else '',
        'is_available': available_quantity > 0,
        'quantity_adjusted': adjusted_quantity != requested_quantity
    }


def lambda_handler(event, _context):
    """
    POST /cart/validate

    Validates cart items against current product availability and returns
    updated items with fresh presigned URLs.

    Request body:
    {
        "items": [
            {"product_id": 25001, "quantity": 2},
            {"product_id": 25002, "quantity": 1}
        ]
    }

    Response:
    {
        "valid_items": [...],      // Items that are available
        "invalid_items": [...],    // Items that are no longer available
        "adjusted_items": [...]    // Items where quantity was reduced
    }
    """
    try:
        # Handle CORS preflight
        http_method = event.get('httpMethod') or event.get('requestContext', {}).get('http', {}).get('method')

        if http_method == 'OPTIONS':
            return {
                'statusCode': 200,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'POST, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
                },
                'body': json.dumps({'message': 'OK'})
            }

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

        # Validate required fields
        if 'items' not in body or not isinstance(body['items'], list):
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'items array is required'})
            }

        items = body['items']

        if len(items) == 0:
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'valid_items': [],
                    'invalid_items': [],
                    'adjusted_items': []
                })
            }

        # Extract product IDs
        product_ids = [str(item['product_id']) for item in items]

        # Fetch current product data
        products = get_products_by_ids(product_ids)

        # Categorize items
        valid_items = []
        invalid_items = []
        adjusted_items = []

        for item in items:
            product_id = str(item['product_id'])
            requested_quantity = int(item['quantity'])

            # Check if product exists
            if product_id not in products:
                invalid_items.append({
                    'product_id': int(product_id),
                    'reason': 'Product no longer exists'
                })
                continue

            product_data = products[product_id]

            # Format cart item with fresh data
            cart_item = format_cart_item(product_id, requested_quantity, product_data)

            # Categorize based on availability
            if not cart_item['is_available']:
                invalid_items.append({
                    'product_id': cart_item['product_id'],
                    'product_name': cart_item['product_name'],
                    'reason': 'Out of stock'
                })
            elif cart_item['quantity_adjusted']:
                adjusted_items.append(cart_item)
            else:
                valid_items.append(cart_item)

        return {
            'statusCode': 200,
            'body': json.dumps({
                'valid_items': valid_items,
                'invalid_items': invalid_items,
                'adjusted_items': adjusted_items,
                'message': f'Validated {len(items)} cart items'
            })
        }

    except ValueError as e:
        print(f"Validation error: {str(e)}")
        return {
            'statusCode': 400,
            'body': json.dumps({'error': str(e)})
        }

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }
