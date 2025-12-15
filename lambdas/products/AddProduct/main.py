# # """ Lambda function to add a product"""
import json
import base64
import boto3
from datetime import datetime, timezone
from decimal import Decimal


from auth_utils import require_role
from multipart import parse_multipart_formdata
from dynamo_utils import normalize_dynamodb_decimals

# # Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')

# # Configuration
PRODUCTS_TABLE_NAME = 'bw3-products-dev'
S3_BUCKET_NAME = 'bw3-images-dev'
S3_FOLDER = 'products'

def upload_images_to_s3(product_id, file_fields):
    """
    Upload images to S3 and return list of S3 object keys.
    
    Args:
        product_id: The product ID
        file_fields: Dictionary of file field names to file content (bytes)
        
    Returns:
        List of S3 object keys
    """
    image_keys = []
    
    for image_idx, (field_name, file_content) in enumerate(file_fields.items(), start=1):
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

def save_product_to_dynamodb(product_id, title, description, price, image_keys):
    """
    Save product to DynamoDB.
    
    Args:
        product_id: Unique product ID
        title: Product title
        description: Product description
        price: Product price
        image_keys: List of S3 object keys for images
    """
    table = dynamodb.Table(PRODUCTS_TABLE_NAME)
    now = datetime.now(timezone.utc).isoformat()
    price = Decimal(price)
    
    item = {
        'product_id': product_id,
        'title': title,
        'description': description,
        'price': price,
        'images': image_keys,
        'created_at': now,
        'updated_at': now
    }
    
    try:
        table.put_item(Item=item)
        print(f"Saved product to DynamoDB: {product_id}")
    except Exception as e:
        print(f"Error saving product to DynamoDB: {e}")
        raise

def generate_product_id():
    """
    Create product id with format: YYNNN (e.g., 25001, 25002)
    Finds the max product_id for current year and adds 1.
    """
    try:
        current_year = datetime.now().strftime('%y')
        table = dynamodb.Table(PRODUCTS_TABLE_NAME)
        year_prefix = current_year

        response = table.scan(
            FilterExpression='begins_with(product_id, :year_prefix)',
            ExpressionAttributeValues={
                ':year_prefix': year_prefix
            }
        )
        items = response.get('Items', [])
        items = [normalize_dynamodb_decimals(item) for item in items]

        max_number = 0
        for item in items:
            product_id = item.get('product_id', '')
            if product_id.startswith(year_prefix) and len(product_id) == 5:
                try:
                    number = int(product_id[2:])
                    max_number = max(max_number, number)
                except ValueError:
                    continue
        next_number = max_number + 1
        product_id = f"{current_year}{next_number:03d}"
        print(f"Generated product ID: {product_id}")
        return product_id
        
    except Exception as e:
        print(f"Error generating product ID: {e}")
        raise

def add_product(event):
    """
    Business logic to add a product.
    """
    try:
        print("Begin adding product")
        body = base64.b64decode(event['body'])
        print(f"Decoded body length: {len(body)}")
        
        content_type = event['headers'].get('content-type') or event['headers'].get('Content-Type')
        print(f"Content-Type: {content_type}")
        
        # Parse the form data
        text_fields, file_fields = parse_multipart_formdata(body, content_type)
        print(f"Parsed text fields: {list(text_fields.keys())}")
        print(f"Parsed file fields: {list(file_fields.keys())}")
        
        # Access form fields directly
        title = text_fields.get('title')
        description = text_fields.get('description')
        price = text_fields.get('price')
        
        print(f"Title: {title}")
        print(f"Description: {description}")
        print(f"Price: {price}")
        
        # Validate required fields
        if not title or not description or not price:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'message': 'Missing required fields',
                    'required': ['title', 'description', 'price']
                })
            }
        
        # Generate new product ID
        product_id = generate_product_id()
        
        # Upload images to S3
        image_keys = []
        if file_fields:
            image_keys = upload_images_to_s3(product_id, file_fields)
            print(f"Uploaded {len(image_keys)} images")
        
        # Save product to DynamoDB
        save_product_to_dynamodb(product_id, title, description, price, image_keys)
        
        user = event.get('user')
        print(f"User: {user}")
        
        # Return success response
        return {
            'statusCode': 201,
            'body': json.dumps({
                'message': 'Product added successfully',
                'product': {
                    'id': product_id,
                    'title': title,
                    'description': description,
                    'price': price,
                    'images': image_keys
                }
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
    print(f"Lambda handler started")
    
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