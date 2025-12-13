# """ Lambda function to add a product"""
import json
from auth_utils import require_role
import base64
import cgi
from io import BytesIO
import boto3
import uuid
from datetime import datetime

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')

# Configuration
PRODUCTS_TABLE_NAME = 'bw3-products-dev'
S3_BUCKET_NAME = 'bw3-images-dev'
S3_FOLDER = 'products'

def parse_multipart_formdata(body_bytes, content_type):
    """
    Parse multipart/form-data without external dependencies.
    Returns a dictionary of field names to values.
    """
    # Parse content type to get boundary
    ctype, pdict = cgi.parse_header(content_type)
    
    if 'boundary' not in pdict:
        raise ValueError("No boundary found in Content-Type header")
    
    # Ensure boundary is bytes
    pdict['boundary'] = pdict['boundary'].encode('utf-8') if isinstance(pdict['boundary'], str) else pdict['boundary']
    
    # Parse multipart form data
    fields = cgi.parse_multipart(BytesIO(body_bytes), pdict)
    
    # Separate text fields and files
    text_fields = {}
    file_fields = {}
    
    for field_name, field_values in fields.items():
        if field_values:
            value = field_values[0]
            # Try to decode as text
            if isinstance(value, bytes):
                try:
                    decoded_value = value.decode('utf-8')
                    text_fields[field_name] = decoded_value
                except UnicodeDecodeError:
                    # Keep as bytes for files
                    file_fields[field_name] = value
            else:
                text_fields[field_name] = value
    
    return text_fields, file_fields

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
        # Generate S3 key: products/product_id:image_id
        s3_key = f"{S3_FOLDER}/{product_id}:{image_idx}"
        
        try:
            # Upload to S3
            s3.put_object(
                Bucket=S3_BUCKET_NAME,
                Key=s3_key,
                Body=file_content,
                ContentType='image/jpeg'  # Adjust based on actual file type if needed
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
    
    item = {
        'product_id': product_id,
        'title': title,
        'description': description,
        'price': price,
        'images': image_keys,
        'created_at': datetime.utcnow().isoformat(),
        'updated_at': datetime.utcnow().isoformat()
    }
    
    try:
        table.put_item(Item=item)
        print(f"Saved product to DynamoDB: {product_id}")
    except Exception as e:
        print(f"Error saving product to DynamoDB: {e}")
        raise

def generate_product_id():
    """
    Create product id with format: YY_NNN (e.g., 25_001, 25_002)
    Uses atomic DynamoDB counter to prevent collisions.
    """
    try:
        from datetime import datetime
        from botocore.exceptions import ClientError
        
        current_year = datetime.now().strftime('%y')
        counter_key = f'COUNTER_{current_year}'
        table = dynamodb.Table(PRODUCTS_TABLE_NAME)
        
        try:
            # Atomic increment - prevents race conditions
            response = table.update_item(
                Key={'product_id': counter_key},
                UpdateExpression='ADD product_count :inc',
                ExpressionAttributeValues={':inc': 1},
                ReturnValues='UPDATED_NEW'
            )
            next_number = int(response['Attributes']['product_count'])
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'ValidationException':
                # Counter doesn't exist, create it
                table.put_item(Item={
                    'product_id': counter_key,
                    'product_count': 1
                })
                next_number = 1
            else:
                raise
        
        # Format: YY_NNN
        product_id = f"{current_year}_{next_number:03d}"
        
        print(f"Generated product ID: {product_id}")
        return product_id
        
    except Exception as e:
        print(f"Failed to generate product id: {e}")
        raise RuntimeError(f"Failed to generate product_id: {e}") from e

def add_product(event):
    """
    Business logic to add a product.
    """
    try:
        print("Starting add_product function")
        
        # Decode base64 body
        body = base64.b64decode(event['body'])
        print(f"Decoded body length: {len(body)}")
        
        # Get content-type header
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
        print(f"Generated product ID: {product_id}")
        
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
                'data': {
                    'product_id': product_id,
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