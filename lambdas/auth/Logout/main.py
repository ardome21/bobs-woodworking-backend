import json

def lambda_handler(event, _context):

    try:
        http_method = event.get('httpMethod') or event.get('requestContext', {}).get('http', {}).get('method')
        if http_method == 'OPTIONS':
            print("Handling OPTIONS preflight request")
            return
        elif http_method == 'POST':
            print("Handling logout request")
            cookie_attributes = f'refresh_token=; HttpOnly; Secure; SameSite=None; Max-Age=0; Path=/'
            return {
                'statusCode': 200,
                'headers': {'Set-Cookie': cookie_attributes},
                'body': json.dumps({'message': 'Successfully logged out'})
            }
        else:
            print(f"Unsupported HTTP method: {http_method}")
            return {
                'statusCode': 405,
                'body': json.dumps({'error': 'Method not allowed'})
            }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': f'Internal server error {e}'
            })
        }