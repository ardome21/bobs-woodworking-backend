# """ Lambda function to add a product"""
import json

from auth_utils import require_role

import base64
from multipart import parse_form_data
from io import BytesIO

def add_product(event):
    """
    Business logic to add a product.
    """
    try:
        # Decode base64 body
        body = base64.b64decode(event['body'])
        
        # Get content-type header
        content_type = event['headers'].get('content-type') or event['headers'].get('Content-Type')
        
        # Parse multipart form data
        environ = {
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': content_type,
            'CONTENT_LENGTH': str(len(body)),
            'wsgi.input': BytesIO(body)
        }
        
        forms, files = parse_form_data(environ)
        
        # Access form fields
        title = forms.get('title')
        description = forms.get('description')
        price = forms.get('price')
        
        print(f"Title: {title}")
        print(f"Description: {description}")
        print(f"Price: {price}")

        for filename, fileinfo in files.items():
            file_content = fileinfo.file.read()
            print(f"Received file: {filename} with content: {file_content[:20]}... (truncated)")
        
        user = event.get('user')
        print(f"User: {user}")
        
    except Exception as e:
        print(f"Error in add_product: {e}")
        raise RuntimeError(f"Failed to add product: {e}") from e

@require_role('admin')
def lambda_handler(event, _context):
    """
    Entry point to lambda function
    """
    try:
        http_method = event.get('httpMethod') or event.get(
            'requestContext', {}).get('http', {}).get('method')
        if http_method == 'OPTIONS':
            print("Handling OPTIONS preflight request")
            return
        if http_method == 'POST': 
            print("Handling POST request")
            return add_product(event)
        else:
            print(f"Unsupported HTTP method: {http_method}")
            return {
                'statusCode': 405,
                'body': json.dumps({'message': 'Method Not Allowed'})
            }
        # print("Begin Script...")
        # print(f"Event body: {event['body']}")
        # is_base64 = event.get('isBase64Encoded', False)
        # print(f"Is base64: {is_base64}")
    
        # body = event['body']
        
        # if is_base64:
        #     # Decode the base64 body
        #     print(f"Undecode Body : {body}")
        #     decoded_body = base64.b64decode(body).decode('utf-8')
        #     print(f"Decoded body: {decoded_body}")
        # else:
        #     decoded_body = body
        #     print(f"Unencoded body: {decoded_body}")
        
        # # Parse the form data
        # # For URL-encoded form data:
        # form_data = parse_qs(decoded_body)
        # print(f"Form data: {form_data}")
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
                'message': 'F',
                'error': f'Internal server error: {e}'
                })
        }