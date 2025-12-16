"""
    Get Products Lambda
    Returns all products
"""

import json
import boto3
from typing import Dict, Any, List, cast

from dynamo_utils import normalize_dynamodb_decimals
from s3_utils import generate_presigned_url

PRODUCTS_TABLE_NAME = 'bw3-products-dev'
S3_BUCKET_NAME = 'bw3-images-dev'

dynamodb = boto3.resource('dynamodb')

def format_product(raw_item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert raw DynamoDB item to formatted product with presigned URLs"""
    try:
        item = cast(Dict[str, Any], normalize_dynamodb_decimals(raw_item))

        image_urls: List[str] = []
        for s3_key in item.get('images', []):
            if isinstance(s3_key, str):
                image_urls.append(generate_presigned_url(S3_BUCKET_NAME ,s3_key))

        return {
            'id': item.get('product_id'),
            'title': item.get('title'),
            'description': item.get('description'),
            'price': item.get('price'),
            'images': image_urls,
            'created_at': item.get('created_at'),
            'updated_at': item.get('updated_at'),
        }
    except Exception as e:
        print(f"Failed to format product: {e}")
        raise RuntimeError(f"Failed to format product: {e}") from e

def get_product_from_id(product_table, product_id):
    """
    Return json with status_code, and body.
        - Body contains product information or error message
    
    :param table: 
    :param product_id
    """
    try:
        print(f"Getting product: {product_id}")
        response = product_table.get_item(Key={'product_id': product_id})
        raw_item = response.get('Item')
        if not raw_item:
            print("[WARNING] Could not find a product with that ID ")
            return {
                'statusCode': 404,
                'body': json.dumps({
                    'message': f'Product with id {product_id} not found'
                }),
            }
        print("Product found")
        product = format_product(raw_item)
        print("Product Formatted")
        return {
            'statusCode': 200,
            'body': json.dumps({
                'product': product
            }),
        }
    except Exception as e:
        print(f"Failed to get product: {e}")
        raise RuntimeError(f"Failed to get product: {e}")from e
    
def get_products(product_table):
    """
    Return json with status_code and body.
        - Body contains list of products or an error message
    
    :param product_table:
    """
    try:
        print("Getting all products")
        response = product_table.scan()
        raw_items = response.get('Items', [])
        print(f"Found {len(raw_items)} products")
        products = [format_product(raw_item) for raw_item in raw_items]
        print(f"Formatted {len(products)} products")
        return {
            'statusCode': 200,
            'body': json.dumps({
                'products': products
            }),
        }
    except Exception as e:
        raise RuntimeError(f"Failed to get products: {e}") from e

def lambda_handler(event, _context):
    try:
        print("Beginning Script...")
        http_method = event.get('httpMethod') or event.get(
            'requestContext', {}).get('http', {}).get('method')
        if http_method == 'OPTIONS':
            print("Handling OPTIONS preflight request")
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'OK'})
            }
        path_params = event.get('pathParameters') or {}
        product_id = path_params.get('id')
        table = dynamodb.Table(PRODUCTS_TABLE_NAME)
        if product_id:
            return get_product_from_id(table, product_id)
        return get_products(table)

    except Exception as e:
        print(f"Unexpected error during Get Products: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Internal server error',
                'error': str(e),
            }),
        }
