import boto3
import json
from boto3.dynamodb.conditions import Key, Attr
from plaid.api import plaid_api
from plaid.model.link_token_create_request import LinkTokenCreateRequest
from plaid.model.link_token_create_request_user import LinkTokenCreateRequestUser
from plaid.model.products import Products
from plaid.model.country_code import CountryCode
from plaid.configuration import Configuration
from plaid.api_client import ApiClient
from plaid import Environment
import jwt

dynamodb = boto3.resource('dynamodb')
userTable = dynamodb.Table('bw3-users-dev')


def get_auth_token(event):
    cookies = event.get('cookies', [])
    for cookie in cookies:
        if cookie.startswith('authToken='):
            return cookie.split('=', 1)[1]
    return None

def verify_auth(event):
    token = get_auth_token(event)
    if not token:
        print("No token found")
        raise Exception("No token found")
    try:
        jwt_secret = boto3.client('ssm').get_parameter(Name='/bw3/jwt-secret-key', WithDecryption=True)['Parameter']['Value']
        payload = jwt.decode(token, jwt_secret, algorithms=['HS256'])
    except jwt.ExpiredSignatureError as e:
        print(f"Expire Signature error: {e}")
        raise e
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {e}")
        raise e
    response = userTable.query(
        KeyConditionExpression=Key('user_id').eq(payload.get('user_id')),
        FilterExpression=Attr('email').eq(payload.get('email'))
    )
    users = response['Items']
    if not users:
        print('No user found found matching bearer token')
        raise Exception("No items")
    if len(users) > 1:
        print('Multiple users found matching bearer token? That cant be?')
        raise Exception('Multiple users found matching bearer token? That cant be?')
    return users[0].get('user_id')


def lambda_handler(event, _context):
    try:
        http_method = event.get('httpMethod') or event.get('requestContext', {}).get('http', {}).get('method')
        print(f"HTTP Method detected: {http_method}")
        if http_method == 'OPTIONS':
            print("Handling OPTIONS preflight request")
            return
        user_id = verify_auth(event)
        ssm_client = boto3.client('ssm')
        client_id = ssm_client.get_parameter(Name='/bw3/plaid/client_id', WithDecryption=True)['Parameter']['Value']
        sandbox_secret = ssm_client.get_parameter(Name='/bw3/plaid/sandbox_secret', WithDecryption=True)['Parameter']['Value']

        configuration = Configuration(
            host=Environment.Sandbox,
            api_key={
                'clientId': client_id,
                'secret': sandbox_secret
            }
        )
        api_client = ApiClient(configuration)
        client = plaid_api.PlaidApi(api_client)
        request = LinkTokenCreateRequest(
            products=[Products("auth"), Products("transactions")],
            client_name="My App",
            country_codes=[CountryCode("US")],
            language="en",
            user=LinkTokenCreateRequestUser(client_user_id=user_id)
        )

        response = client.link_token_create(request)
        return {
            'statusCode': 200,
            'body': json.dumps(response.to_dict())
        }
        
    except Exception as e:
        print(f'Error: {str(e)}')  # Add logging
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }