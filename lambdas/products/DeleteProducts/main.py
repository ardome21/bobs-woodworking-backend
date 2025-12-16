"""
Delete Products Lambda
Deletes one or multiple products and their associated S3 images
"""

import json
import boto3
from typing import List, Dict, Any

from auth_utils import require_role

PRODUCTS_TABLE_NAME = 'bw3-products-dev'
S3_BUCKET_NAME = 'bw3-images-dev'

dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')


def delete_product_images(product_id: str) -> None:
    """
    Delete all images associated with a product from S3

    Args:
        product_id: The product ID
    """
    try:
        prefix = f"products/{product_id}/"
        response = s3.list_objects_v2(Bucket=S3_BUCKET_NAME, Prefix=prefix)
        if 'Contents' in response:
            objects_to_delete = [{'Key': obj['Key']} for obj in response['Contents']]
            if objects_to_delete:
                s3.delete_objects(
                    Bucket=S3_BUCKET_NAME,
                    Delete={'Objects': objects_to_delete}
                )
                print(f"Deleted {len(objects_to_delete)} images for product {product_id}")
        else:
            print(f"No images found for product {product_id}")
    except Exception as e:
        print(f"Error deleting images for product {product_id}: {e}")
        raise


def delete_single_product(table, product_id: str) -> Dict[str, Any]:
    """
    Delete a single product from DynamoDB and S3

    Args:
        table: DynamoDB table resource
        product_id: The product ID to delete

    Returns:
        Result dictionary with success status
    """
    try:
        response = table.get_item(Key={'product_id': product_id})
        if 'Item' not in response:
            return {
                'product_id': product_id,
                'success': False,
                'error': 'Product not found'
            }
        delete_product_images(product_id)
        table.delete_item(Key={'product_id': product_id})
        print(f"Successfully deleted product {product_id}")
        return {
            'product_id': product_id,
            'success': True
        }

    except Exception as e:
        print(f"Error deleting product {product_id}: {e}")
        return {
            'product_id': product_id,
            'success': False,
            'error': str(e)
        }


def delete_products(event) -> Dict[str, Any]:
    """
    Delete one or multiple products

    Args:
        event: Lambda event containing product_id or product_ids

    Returns:
        Response dictionary
    """
    try:
        table = dynamodb.Table(PRODUCTS_TABLE_NAME)
        body = json.loads(event['body']) if isinstance(
            event.get('body'), str) else event.get('body', {})
        path_params = event.get('pathParameters') or {}
        product_id = path_params.get('id')
        product_ids = body.get('product_ids', [])
        results = []
        if product_id:
            result = delete_single_product(table, product_id)
            results.append(result)
        elif product_ids:
            if not isinstance(product_ids, list):
                return {
                    'statusCode': 400,
                    'body': json.dumps({
                        'message': 'product_ids must be an array'
                    })
                }
            for pid in product_ids:
                result = delete_single_product(table, pid)
                results.append(result)
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'message': 'Either product_id (path parameter) or product_ids (body) is required'
                })
            }

        # Check if any deletions failed
        failed = [r for r in results if not r['success']]
        succeeded = [r for r in results if r['success']]

        status_code = 200 if not failed else (207 if succeeded else 400)

        return {
            'statusCode': status_code,
            'body': json.dumps({
                'message': f'Deleted {len(succeeded)} product(s), {len(failed)} failed',
                'results': results
            })
        }

    except Exception as e:
        print(f"Error in delete_products: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Internal server error',
                'error': str(e)
            })
        }


@require_role('admin')
def lambda_handler(event, _context):
    """
    Entry point to lambda function
    Requires admin role to delete products
    """
    print("Lambda handler started")

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
        if http_method == 'DELETE':
            print("Handling DELETE request")
            return delete_products(event)
        else:
            print(f"Unsupported HTTP method: {http_method}")
            return {
                'statusCode': 405,
                'body': json.dumps({'message': 'Method Not Allowed'})
            }
    except Exception as e:
        print(f"Error in lambda_handler: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Internal server error',
                'error': str(e)
            })
        }
