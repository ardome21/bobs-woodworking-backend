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

def lambda_handler(event, _context):
    try:
        table = dynamodb.Table(PRODUCTS_TABLE_NAME)

        response = table.scan()
        raw_items = response.get('Items', [])

        products: List[Dict[str, Any]] = []

        for raw_item in raw_items:
            # Tell Pylance this is a dict after conversion
            item = cast(Dict[str, Any], decimal_to_native(raw_item))

            image_urls: List[str] = []
            for s3_key in item.get('images', []):
                if isinstance(s3_key, str):
                    image_urls.append(generate_presigned_url(s3_key))

            product = {
                'product_id': item.get('product_id'),
                'title': item.get('title'),
                'description': item.get('description'),
                'price': item.get('price'),
                'images': image_urls,
                'created_at': item.get('created_at'),
                'updated_at': item.get('updated_at'),
            }

            products.append(product)

        return {
            'statusCode': 200,
            'body': json.dumps({
                'products': products
            }),
        }

    except Exception as e:
        print(f"Unexpected error during Get Products: {e}")

        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Internal server error',
                'error': str(e),
            }),
        }
