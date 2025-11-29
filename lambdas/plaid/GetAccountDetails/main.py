import json
import boto3
from boto3.dynamodb.conditions import Key, Attr
from plaid.api import plaid_api
from plaid.model.accounts_get_request import AccountsGetRequest
from plaid.configuration import Configuration
from plaid.api_client import ApiClient
from plaid import Environment
import jwt


class BadRequestException(Exception):
    pass

dynamodb = boto3.resource('dynamodb')
userTable = dynamodb.Table('bw3-users-dev')
accessTable = dynamodb.Table('bw3-plaid-connections-dev')

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

def get_access_token(user_id, institution):

    response = accessTable.query(
        KeyConditionExpression=Key('user_id').eq(user_id),
        FilterExpression=Attr('institution_name').eq(institution)
    )
    token = response['Items']
    if not token:
        raise BadRequestException(f"No plaid token found for {user_id} and {institution}")
    if len(token) > 1:
        raise BadRequestException(f"Multiple tokens found for {user_id} and {institution}")
    item = response['Items'][0]
    encrypted_access_token = item['access_token']
    jwt_secret = boto3.client('ssm').get_parameter(Name='/bw3/jwt-secret-key', WithDecryption=True)['Parameter']['Value']
    decrypted_access_token = jwt.decode(encrypted_access_token, jwt_secret, algorithms=['HS256'])
    return decrypted_access_token['access_token']


def lambda_handler(event, _context):
    try:
        http_method = event.get('httpMethod') or event.get(
            'requestContext', {}).get('http', {}).get('method')
        if http_method == 'OPTIONS':
            print("Handling OPTIONS preflight request")
            return
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
        
        print(f'Event: {event}')
        if isinstance(event['body'], str):
            body = json.loads(event['body'])
        else:
            body = event['body']
        institution = body['institution']
        user_id = verify_auth(event)
        access_token = get_access_token(user_id, institution)
        request = AccountsGetRequest(access_token=access_token)
        response = client.accounts_get(request)        
        accounts = []
        for account in response.accounts:
            accounts.append({
                'account_id': account.account_id,
                'name': account.name,
                'type': str(account.type),
                'subtype': str(account.subtype) if account.subtype else None,
                'balance': {
                    'available': float(account.balances.available) if account.balances.available else None,
                    'current': float(account.balances.current) if account.balances.current else None
                }
            })
            
        print(f'Account: {accounts}')
        
        return {
            'statusCode': 200,
            'body': json.dumps({'accounts': accounts})
        }
    except BadRequestException as e:
        print(f'Bad Request: {str(e)}')
        return {
            'statusCode': 400,
            'body': json.dumps({'error': str(e)})
        }
    except Exception as e:
        print(f'Error: {str(e)}')
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }