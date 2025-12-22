"""Lambda function to create an order after successful payment"""
import json
import boto3
import stripe
import time
import random
import string
from datetime import datetime, timezone
from decimal import Decimal
from auth_utils import require_role

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
ses = boto3.client('ses', region_name='us-east-1')
ssm = boto3.client('ssm', region_name='us-east-1')

# Configuration
ORDERS_TABLE_NAME = 'bw3-orders-dev'
PRODUCTS_TABLE_NAME = 'bw3-products-dev'
SENDER_EMAIL = 'noreply@bobs-woodworks.com'

# Cache for Stripe API key
_stripe_api_key = None


def get_stripe_api_key():
    """Get Stripe API key from Parameter Store (cached)"""
    global _stripe_api_key

    if _stripe_api_key is None:
        try:
            response = ssm.get_parameter(
                Name='/bw3/stripe-secret-key/test',
                WithDecryption=True
            )
            _stripe_api_key = response['Parameter']['Value']
        except Exception as e:
            print(f"Error retrieving Stripe API key: {e}")
            raise RuntimeError("Failed to retrieve Stripe API key")

    return _stripe_api_key


def generate_order_id():
    """
    Generate unique order ID in format: ORD-{timestamp}-{random}
    Example: ORD-1734479520-A3F9
    """
    timestamp = int(time.time())
    random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f"ORD-{timestamp}-{random_suffix}"


def verify_payment_intent(payment_intent_id):
    """
    Verify that the Stripe Payment Intent was successful.

    Args:
        payment_intent_id: Stripe Payment Intent ID

    Returns:
        Payment Intent object if successful

    Raises:
        RuntimeError if payment was not successful
    """
    stripe.api_key = get_stripe_api_key()

    try:
        payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)

        if payment_intent.status != 'succeeded':
            raise RuntimeError(f"Payment intent status is '{payment_intent.status}', expected 'succeeded'")

        print(f"Payment Intent {payment_intent_id} verified successfully")
        return payment_intent

    except stripe.error.StripeError as e:
        print(f"Stripe error verifying payment: {e}")
        raise RuntimeError(f"Payment verification failed: {str(e)}")


def get_product_details(product_ids):
    """
    Get product details from DynamoDB.

    Args:
        product_ids: List of product IDs

    Returns:
        Dict mapping product_id to product details
    """
    products_table = dynamodb.Table(PRODUCTS_TABLE_NAME)
    products = {}

    for product_id in product_ids:
        try:
            response = products_table.get_item(Key={'product_id': str(product_id)})

            if 'Item' not in response:
                raise ValueError(f"Product {product_id} not found")

            products[str(product_id)] = response['Item']

        except Exception as e:
            print(f"Error fetching product {product_id}: {e}")
            raise

    return products


def calculate_order_total(items, products):
    """
    Calculate order total and enrich items with product details.

    Args:
        items: List of {product_id, quantity}
        products: Dict of product details

    Returns:
        Tuple of (enriched_items, total_amount)
    """
    enriched_items = []
    total_amount = Decimal('0')

    for item in items:
        product_id = str(item['product_id'])
        quantity = int(item['quantity'])

        if product_id not in products:
            raise ValueError(f"Product {product_id} not found")

        product = products[product_id]
        unit_price = Decimal(str(product['price']))
        subtotal = unit_price * quantity

        enriched_items.append({
            'product_id': product_id,
            'product_name': product['title'],
            'quantity': quantity,
            'unit_price': unit_price,
            'subtotal': subtotal
        })

        total_amount += subtotal

    return enriched_items, total_amount


def save_order_to_dynamodb(order_data):
    """Save order to DynamoDB"""
    orders_table = dynamodb.Table(ORDERS_TABLE_NAME)

    try:
        orders_table.put_item(Item=order_data)
        print(f"Order {order_data['order_id']} saved successfully")
    except Exception as e:
        print(f"Error saving order to DynamoDB: {e}")
        raise


def send_order_confirmation_email(user_email, user_name, order_id, total_amount, items, shipping_address):
    """
    Send order confirmation email via SES.

    Args:
        user_email: Customer email
        user_name: Customer name
        order_id: Order ID
        total_amount: Total order amount
        items: List of order items
        shipping_address: Shipping address dict
    """
    subject = "Order Confirmation - Bob's Woodworking"

    # Build items list HTML
    items_html = ""
    for item in items:
        items_html += f"""
        <li>
            <strong>{item['product_name']}</strong> -
            Quantity: {item['quantity']} -
            ${float(item['subtotal']):.2f}
        </li>
        """

    # Format shipping address
    formatted_address = f"""
    {shipping_address['name']}<br>
    {shipping_address['street']}<br>
    {shipping_address['city']}, {shipping_address['state']} {shipping_address['zip']}<br>
    {shipping_address['country']}
    """

    body = f"""
    <html>
    <body>
        <h1>Order Confirmation - Bob's Woodworking</h1>
        <p>Hi {user_name},</p>
        <p>Thank you for your order! Your order has been confirmed and is being processed.</p>

        <h2>Order Details</h2>
        <p><strong>Order ID:</strong> {order_id}</p>
        <p><strong>Total:</strong> ${float(total_amount):.2f}</p>

        <h3>Items:</h3>
        <ul>
            {items_html}
        </ul>

        <h3>Shipping Address:</h3>
        <p>{formatted_address}</p>

        <p>We'll send you another email when your order ships.</p>

        <p>Best regards,<br>Bob's Woodworking Team</p>
    </body>
    </html>
    """

    try:
        ses.send_email(
            Source=SENDER_EMAIL,
            Destination={'ToAddresses': [user_email]},
            Message={
                'Subject': {'Data': subject},
                'Body': {'Html': {'Data': body}}
            }
        )
        print(f"Order confirmation email sent to {user_email}")
    except Exception as e:
        print(f"Error sending confirmation email: {e}")
        # Don't raise - we don't want to fail the order if email fails


@require_role('user', 'admin')
def lambda_handler(event, _context):
    """Main Lambda handler for creating orders"""
    try:
        http_method = event.get('httpMethod') or event.get('requestContext', {}).get('http', {}).get('method')
        print(f"HTTP Method detected: {http_method}")

        if http_method != 'POST':
            return {
                'statusCode': 405,
                'body': json.dumps({'error': f'Method {http_method} Not Allowed'})
            }

        # Parse request body
        if isinstance(event['body'], str):
            body = json.loads(event['body'])
        else:
            body = event['body']

        # Extract user info from JWT (injected by @require_role decorator)
        user = event.get('user', {})
        user_id = user.get('user_id')
        user_email = user.get('email')
        user_name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip() or user_email

        print(f"Creating order for user: {user_id} ({user_email})")

        # Validate required fields
        required_fields = ['items', 'shipping_address', 'payment_intent_id']
        missing_fields = [f for f in required_fields if f not in body]

        if missing_fields:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': f'Missing required fields: {", ".join(missing_fields)}'})
            }

        items = body['items']
        shipping_address = body['shipping_address']
        payment_intent_id = body['payment_intent_id']

        # Validate items
        if not isinstance(items, list) or len(items) == 0:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Items must be a non-empty array'})
            }

        # Validate shipping address (name is optional if user is logged in)
        required_address_fields = ['street', 'city', 'state', 'zip', 'country']
        missing_address_fields = [f for f in required_address_fields if f not in shipping_address]

        if missing_address_fields:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': f'Missing shipping address fields: {", ".join(missing_address_fields)}'})
            }

        # If name is not provided in shipping address, use user's name from token
        if 'name' not in shipping_address or not shipping_address['name']:
            shipping_address['name'] = user_name

        # 1. Verify payment intent with Stripe
        payment_intent = verify_payment_intent(payment_intent_id)

        # Extract payment method details
        payment_method_id = payment_intent.payment_method
        payment_info = {'payment_method': 'card', 'payment_intent_id': payment_intent_id}

        # Get payment method details if available
        if payment_method_id:
            try:
                stripe.api_key = get_stripe_api_key()
                payment_method = stripe.PaymentMethod.retrieve(payment_method_id)
                if payment_method.card:
                    payment_info['last4'] = payment_method.card.last4
                    payment_info['brand'] = payment_method.card.brand
            except Exception as e:
                print(f"Could not retrieve payment method details: {e}")

        # 2. Get product details
        product_ids = [item['product_id'] for item in items]
        products = get_product_details(product_ids)

        # 3. Calculate total and enrich items
        enriched_items, total_amount = calculate_order_total(items, products)

        # 4. Generate order ID
        order_id = generate_order_id()
        timestamp = datetime.now(timezone.utc).isoformat()

        # 5. Create order data
        order_data = {
            'user_id': user_id,
            'order_id': order_id,
            'order_status': 'paid',
            'total_amount': total_amount,
            'items': enriched_items,
            'shipping_address': shipping_address,
            'payment_info': payment_info,
            'created_at': timestamp,
            'updated_at': timestamp,
            'paid_at': timestamp
        }

        # 6. Save order to DynamoDB
        save_order_to_dynamodb(order_data)

        # 7. Send confirmation email
        send_order_confirmation_email(
            user_email=user_email,
            user_name=user_name,
            order_id=order_id,
            total_amount=total_amount,
            items=enriched_items,
            shipping_address=shipping_address
        )

        # 8. Return success response
        return {
            'statusCode': 201,
            'body': json.dumps({
                'order_id': order_id,
                'total_amount': float(total_amount),
                'status': 'paid',
                'message': 'Order created successfully. Confirmation email sent.'
            })
        }

    except ValueError as e:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': str(e)})
        }

    except RuntimeError as e:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': str(e)})
        }

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }
