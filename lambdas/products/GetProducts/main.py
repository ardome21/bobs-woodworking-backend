"""
    Get Products Lambda
    Returns all products
"""

import json
import boto3
from datetime import datetime, timezone
from typing import Dict, Any, List, cast
from dynamo_utils import decimal_to_native

PRODUCTS_TABLE_NAME = 'bw3-products-dev'
S3_BUCKET_NAME = 'bw3-images-dev'
S3_URL_EXPIRATION = 3600  # seconds (1 hour)

dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')


def generate_presigned_url(s3_key: str) -> str:
    return s3.generate_presigned_url(
        ClientMethod='get_object',
        Params={
            'Bucket': S3_BUCKET_NAME,
            'Key': s3_key,
        },
        ExpiresIn=S3_URL_EXPIRATION,
    )


def format_product(raw_item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert raw DynamoDB item to formatted product with presigned URLs"""
    try:
        item = cast(Dict[str, Any], decimal_to_native(raw_item))

        image_urls: List[str] = []
        for s3_key in item.get('images', []):
            if isinstance(s3_key, str):
                image_urls.append(generate_presigned_url(s3_key))

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
        response = product_table.get_item(Key={'product_id': product_id})
        raw_item = response.get('Item')
        if not raw_item:
            return {
                'statusCode': 404,
                'body': json.dumps({
                    'message': f'Product with id {product_id} not found'
                }),
            }
        product = format_product(raw_item)
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
        # Get all products
        response = product_table.scan()
        raw_items = response.get('Items', [])

        products = [format_product(raw_item) for raw_item in raw_items]

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
