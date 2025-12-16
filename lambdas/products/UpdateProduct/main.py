"""
Update Product Lambda
Updates an existing product with new data and/or images
"""

import json
import base64
import boto3
from datetime import datetime, timezone
from decimal import Decimal
from typing import Dict, Any, List

from auth_utils import require_role
from multipart import parse_multipart_formdata

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')

# Configuration
PRODUCTS_TABLE_NAME = 'bw3-products-dev'
S3_BUCKET_NAME = 'bw3-images-dev'
S3_FOLDER = 'products'


def delete_product_images(product_id: str, image_keys_to_keep: List[str] = None) -> None:
    """
    Delete images from S3 that are not in the keep list

    Args:
        product_id: The product ID
        image_keys_to_keep: List of S3 keys to keep (don't delete)
    """
    try:
        image_keys_to_keep = image_keys_to_keep or []
        prefix = f"{S3_FOLDER}/{product_id}/"

        response = s3.list_objects_v2(Bucket=S3_BUCKET_NAME, Prefix=prefix)
        if 'Contents' in response:
            for obj in response['Contents']:
                key = obj['Key']
                if key not in image_keys_to_keep:
                    s3.delete_object(Bucket=S3_BUCKET_NAME, Key=key)
                    print(f"Deleted old image: {key}")
    except Exception as e:
        print(f"Error deleting old images: {e}")
        raise


def upload_images_to_s3(product_id: str, file_fields: Dict[str, bytes], start_index: int = 1) -> List[str]:
    """
    Upload new images to S3 and return list of S3 object keys

    Args:
        product_id: The product ID
        file_fields: Dictionary of file field names to file content (bytes)
        start_index: Starting index for image numbering

    Returns:
        List of S3 object keys
    """
    image_keys = []

    for image_idx, (field_name, file_content) in enumerate(file_fields.items(), start=start_index):
        s3_key = f"{S3_FOLDER}/{product_id}/{image_idx}"

        try:
            s3.put_object(
                Bucket=S3_BUCKET_NAME,
                Key=s3_key,
                Body=file_content,
                ContentType='image/jpeg'
            )

            image_keys.append(s3_key)
            print(f"Uploaded image to S3: {s3_key}")

        except Exception as e:
            print(f"Error uploading image {image_idx} to S3: {e}")
            raise

    return image_keys


def update_product(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Business logic to update a product
    """
    try:
        print("Begin updating product")

        # Get product ID from path parameters
        path_params = event.get('pathParameters') or {}
        product_id = path_params.get('id')

        if not product_id:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'message': 'Product ID is required in path'
                })
            }

        # Check if product exists
        table = dynamodb.Table(PRODUCTS_TABLE_NAME)
        existing_product = table.get_item(Key={'product_id': product_id})

        if 'Item' not in existing_product:
            return {
                'statusCode': 404,
                'body': json.dumps({
                    'message': f'Product with id {product_id} not found'
                })
            }

        current_product = existing_product['Item']

        # Parse multipart form data
        body = base64.b64decode(event['body'])
        print(f"Decoded body length: {len(body)}")

        content_type = event['headers'].get('content-type') or event['headers'].get('Content-Type')
        print(f"Content-Type: {content_type}")

        text_fields, file_fields = parse_multipart_formdata(body, content_type)
        print(f"Parsed text fields: {list(text_fields.keys())}")
        print(f"Parsed file fields: {list(file_fields.keys())}")

        # Get updated fields (use existing values if not provided)
        title = text_fields.get('title', current_product.get('title'))
        description = text_fields.get('description', current_product.get('description'))
        price = text_fields.get('price', str(current_product.get('price')))

        print(f"Title: {title}")
        print(f"Description: {description}")
        print(f"Price: {price}")

        # Handle images
        # Parse existing_images field (JSON array of S3 keys to keep)
        existing_images_json = text_fields.get('existing_images', '[]')
        try:
            existing_images_to_keep = json.loads(existing_images_json) if isinstance(existing_images_json, str) else existing_images_json
            if not isinstance(existing_images_to_keep, list):
                existing_images_to_keep = []
        except json.JSONDecodeError:
            print(f"Warning: Could not parse existing_images: {existing_images_json}")
            existing_images_to_keep = []

        print(f"Existing images to keep: {existing_images_to_keep}")
        print(f"New images to upload: {len(file_fields)}")

        # Start with existing images that should be kept
        final_image_keys = existing_images_to_keep.copy()

        # Upload new images if provided
        if file_fields:
            # Calculate starting index for new images
            # Find the max index from existing images
            max_index = 0
            for key in existing_images_to_keep:
                # Extract index from key like "products/25002/3"
                try:
                    index = int(key.split('/')[-1])
                    max_index = max(max_index, index)
                except (ValueError, IndexError):
                    pass

            start_index = max_index + 1
            new_image_keys = upload_images_to_s3(product_id, file_fields, start_index)
            final_image_keys.extend(new_image_keys)
            print(f"Uploaded {len(new_image_keys)} new images starting at index {start_index}")

        # Delete images from S3 that are no longer in the final list
        delete_product_images(product_id, final_image_keys)

        image_keys = final_image_keys

        # Update product in DynamoDB
        now = datetime.now(timezone.utc).isoformat()

        item = {
            'product_id': product_id,
            'title': title,
            'description': description,
            'price': Decimal(str(price)),
            'images': image_keys,
            'created_at': current_product.get('created_at', now),
            'updated_at': now
        }

        table.put_item(Item=item)
        print(f"Updated product in DynamoDB: {product_id}")

        # Return success response
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Product updated successfully',
                'product': {
                    'id': product_id,
                    'title': title,
                    'description': description,
                    'price': str(price),
                    'images': image_keys
                }
            })
        }

    except Exception as e:
        print(f"Error in update_product: {e}")
        raise RuntimeError(f"Failed to update product: {e}") from e


@require_role('admin')
def lambda_handler(event, _context):
    """
    Entry point to lambda function
    Requires admin role to update products
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

        if http_method == 'PUT':
            print("Handling PUT request")
            return update_product(event)
        else:
            print(f"Unsupported HTTP method: {http_method}")
            return {
                'statusCode': 405,
                'body': json.dumps({'message': 'Method Not Allowed'})
            }

    except RuntimeError as re:
        print(f"Runtime Error Updating Product: {re}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Failed to update product',
                'error': str(re)
            })
        }
    except Exception as e:
        print(f"Error Updating Product: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Internal server error',
                'error': str(e)
            })
        }
