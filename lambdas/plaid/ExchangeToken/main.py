import json
import boto3
from boto3.dynamodb.conditions import Key, Attr
from datetime import datetime
from plaid.api import plaid_api
from plaid.model.item_public_token_exchange_request import ItemPublicTokenExchangeRequest
from plaid.model.institutions_get_by_id_request import InstitutionsGetByIdRequest
from plaid.model.country_code import CountryCode
from plaid.configuration import Configuration
from plaid.api_client import ApiClient
from plaid import Environment
from datetime import timezone, timedelta
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

def exchange_public_token(client, public_token):
    request = ItemPublicTokenExchangeRequest(public_token=public_token)
    response = client.item_public_token_exchange(request)
    
    access_token = response['access_token']
    item_id = response['item_id']
    return {
        'access_token': access_token,
        'item_id': item_id
    }

def get_institution_name(client, access_token):
    """Get institution name for"""
    try:
        from plaid.model.item_get_request import ItemGetRequest
        request = ItemGetRequest(access_token=access_token)
        response = client.item_get(request)
        institution_id = response['item']['institution_id']
        inst_request = InstitutionsGetByIdRequest(
            institution_id=institution_id,
            country_codes=[CountryCode('US')]
        )
        inst_response = client.institutions_get_by_id(inst_request)
        return inst_response['institution']['name']
    except Exception as e:
        print(f"Could not fetch institution name: {e}")
        return None

def encode_access_token(access_token, jwt_secret):
    """Encode the access token using JWT"""
    try:
        payload = {
            'access_token': access_token,
            'exp': datetime.now(timezone.utc) + timedelta(days=365)
        }
        encoded_token = jwt.encode(payload, jwt_secret, algorithm='HS256')
        return encoded_token
    except Exception as e:
        print(f"JWT encoding error: {e}")
        return access_token
    
def store_plaid_connection(user_id, access_token, item_id, institution_name):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('plaid-connections-dev')
    response = table.scan(
        FilterExpression=Attr('user_id').eq(user_id) & Attr('institution_name').eq(institution_name)
    )
    items = response.get('Items', [])
    for existing_item in items:
        print(f"Existing item found: {existing_item}")
        table.delete_item(
            Key={
                'user_id': existing_item['user_id'],
                'item_id': existing_item['item_id']
            }
        )
    item = {
        'user_id': user_id,
        'item_id': item_id,
        'institution_name': institution_name,
        'access_token': access_token,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'status': 'active'
    }
    table.put_item(Item=item)
    return item

def lambda_handler(event, context):
    http_method = event.get('httpMethod') or event.get('requestContext', {}).get('http', {}).get('method')
    print(f"HTTP Method detected: {http_method}")
    
    if http_method == 'OPTIONS':
        print("Handling OPTIONS preflight request")
        return
    try:
        http_method = event.get('httpMethod') or event.get(
            'requestContext', {}).get('http', {}).get('method')
        if http_method == 'OPTIONS':
            print("Handling OPTIONS preflight request")
            return
        user_id = verify_auth(event)
        ssm_client = boto3.client('ssm')
        client_id = ssm_client.get_parameter(Name='/bw3/plaid/client_id', WithDecryption=True)['Parameter']['Value']
        sandbox_secret = ssm_client.get_parameter(Name='/bw3/plaid/sandbox_secret', WithDecryption=True)['Parameter']['Value']
        jwt_secret = ssm_client.get_parameter(Name='/bw3/jwt-secret-key', WithDecryption=True)['Parameter']['Value']

        configuration = Configuration(
            host=Environment.Sandbox,
            api_key={
                'clientId': client_id,
                'secret': sandbox_secret
            }
        )
        api_client = ApiClient(configuration)
        client = plaid_api.PlaidApi(api_client)
        if not client:
            raise Exception("Plaid client not initialized")
        print(f"Plaid client initialized")
        
        if isinstance(event['body'], str):
            body = json.loads(event['body'])
        else:
            body = event['body']
        public_token = body['public_token']
        if not public_token:
            raise Exception("No public token provided")
        print(f"Public token received for {user_id}")
        tokens = exchange_public_token(client, public_token) 
        if not (tokens and tokens['access_token'] and tokens['item_id']):
            raise Exception("No tokens received")
        institution_name = get_institution_name(client, tokens['access_token'])
        encrypted_access_token = encode_access_token(tokens['access_token'], jwt_secret)
        store_plaid_connection(
            user_id=user_id,
            access_token=encrypted_access_token,
            item_id=tokens['item_id'],
            institution_name=institution_name
        )
        print(f"Stored Plaid connection for user {user_id}")
        return {
            'statusCode': 200,
            'body': json.dumps({
                'success': True,
                'item_id': tokens['item_id'],
                'institution_name': institution_name,
                'message': 'Bank account connected successfully'
            })
        }
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }