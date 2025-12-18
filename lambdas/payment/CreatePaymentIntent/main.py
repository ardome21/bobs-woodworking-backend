"""Lambda function to create a Stripe Payment Intent"""
import json
import boto3
import stripe
from decimal import Decimal

# Initialize AWS clients
ssm = boto3.client('ssm', region_name='us-east-1')

# Cache for Stripe API key
_stripe_api_key = None

def get_stripe_api_key():
    """
    Get Stripe API key from AWS Systems Manager Parameter Store.
    Caches the key to avoid repeated SSM calls.
    """
    global _stripe_api_key

    if _stripe_api_key is None:
        try:
            response = ssm.get_parameter(
                Name='/bw3/stripe-secret-key/test',
                WithDecryption=True
            )
            _stripe_api_key = response['Parameter']['Value']
            print("Stripe API key retrieved from Parameter Store")
        except Exception as e:
            print(f"Error retrieving Stripe API key from Parameter Store: {e}")
            raise RuntimeError("Failed to retrieve Stripe API key")

    return _stripe_api_key


def create_payment_intent(amount, currency='usd'):
    """
    Create a Stripe Payment Intent.

    Args:
        amount: Amount in dollars (will be converted to cents)
        currency: Currency code (default: usd)

    Returns:
        Payment Intent object from Stripe
    """
    # Set Stripe API key
    stripe.api_key = get_stripe_api_key()

    # Convert amount to cents (Stripe uses smallest currency unit)
    amount_cents = int(float(amount) * 100)

    try:
        # Create Payment Intent
        payment_intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency=currency,
            automatic_payment_methods={'enabled': True}
        )

        print(f"Payment Intent created: {payment_intent.id}, Amount: {amount_cents} cents")
        return payment_intent

    except stripe.error.InvalidRequestError as e:
        print(f"Invalid Stripe request: {e}")
        raise RuntimeError(f"Invalid payment request: {str(e)}")
    except stripe.error.AuthenticationError as e:
        print(f"Stripe authentication error: {e}")
        raise RuntimeError("Payment service authentication failed")
    except stripe.error.StripeError as e:
        print(f"Stripe error: {e}")
        raise RuntimeError(f"Payment service error: {str(e)}")


def lambda_handler(event, _context):
    """Main Lambda handler for creating Payment Intents"""
    try:
        http_method = event.get('httpMethod') or event.get('requestContext', {}).get('http', {}).get('method')
        print(f"HTTP Method detected: {http_method}")

        if http_method != 'POST':
            print(f"Unsupported HTTP method: {http_method}")
            return {
                'statusCode': 405,
                'body': json.dumps({'error': f'Method {http_method} Not Allowed'})
            }

        # Parse request body
        if isinstance(event['body'], str):
            body = json.loads(event['body'])
        else:
            body = event['body']

        # Validate required fields
        if 'amount' not in body:
            print("Missing required field: amount")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing required field: amount'})
            }

        amount = body['amount']
        currency = body.get('currency', 'usd')

        # Validate amount
        try:
            amount_float = float(amount)
            if amount_float <= 0:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Amount must be greater than 0'})
                }
        except (ValueError, TypeError):
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid amount format'})
            }

        print(f"Creating Payment Intent for amount: ${amount_float} {currency}")

        # Create Payment Intent
        payment_intent = create_payment_intent(amount_float, currency)

        # Return client_secret and payment_intent_id
        return {
            'statusCode': 200,
            'body': json.dumps({
                'client_secret': payment_intent.client_secret,
                'payment_intent_id': payment_intent.id
            })
        }

    except ValueError as e:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': f'Invalid request: {str(e)}'})
        }

    except RuntimeError as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }
