# """ Lambda function to add a product"""
import json

from auth_utils import require_role

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
            pass
        else:
            print("Invalid request")
            return {
                'statusCode': 400,
                'body': json.dumps({'message': 'Invalid request'})
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
        return {
            'statusCode': 200, 
            'body': json.dumps({'message': 'Successfully exited script'})
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