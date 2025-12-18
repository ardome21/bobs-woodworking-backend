"""Lambda function to handle OPTIONS preflight requests for payment endpoints"""
import json


def lambda_handler(event, _context):
    """Handle OPTIONS preflight requests"""
    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'OK'})
    }
