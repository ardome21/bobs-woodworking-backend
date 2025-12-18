# Bob's Woodworking Backend - Claude Instructions

## Architecture Overview

This is a Python-based AWS Lambda backend for Bob's Woodworking application.

## Core Architecture Patterns

### 1. Lambda Function Structure

Each Lambda follows a standard pattern:

**Handler Pattern:**
```python
def lambda_handler(event, context):
    """Main Lambda handler"""
    # 1. Authentication/Authorization
    # 2. Parse/validate input
    # 3. Business logic
    # 4. Return response
```

**Organization:**
- Each Lambda in its own directory with `main.py`
- Group related Lambdas by domain (e.g., `lambdas/products/`, `lambdas/auth/`)
- Shared utilities in Lambda layers

### 2. Security First

**Authentication:**
- Use the `@require_role` decorator from `auth_utils` layer for protected endpoints
- Validate JWT tokens from Cognito
- Check user roles/permissions before operations

**Example:**
```python
from auth_utils import require_role

@require_role(['admin', 'manager'])
def lambda_handler(event, context):
    # Only admins and managers can access
    pass
```

**Input Validation:**
- Always validate required fields exist
- Validate data types before using
- Sanitize user input before database operations
- Use try/except blocks for error handling

### 3. AWS Service Patterns

**DynamoDB:**
- Use `boto3.resource('dynamodb')` for table operations
- Always normalize Decimal types when returning JSON responses
- Use the `normalize_dynamodb_decimals` utility from `dynamo_utils` layer

**S3:**
- Use `boto3.client('s3')` for file operations
- Store S3 keys in DynamoDB, not the actual files
- Handle file uploads with proper ContentType headers

**Configuration:**
- Define table names, bucket names, and other config at top of file
- Use environment variables for environment-specific values
- Never hardcode ARNs or resource names inline

### 4. Response Standards

**Success Response:**
```python
{
    'statusCode': 200,
    'body': json.dumps(data)
}
```

**Error Response:**
```python
{
    'statusCode': 400/403/500,
    'body': json.dumps({'error': 'Descriptive error message'})
}
```

### 5. Shared Utilities (Lambda Layers)

Use Lambda layers for shared code:
- `auth_utils`: Authentication and authorization helpers
- `multipart`: Multipart form data parsing
- `dynamo_utils`: DynamoDB utility functions
- Add more layers as needed for shared functionality

**Import from layers:**
```python
from auth_utils import require_role
from multipart import parse_multipart_formdata
from dynamo_utils import normalize_dynamodb_decimals
```

### 6. Error Handling

**Pattern:**
```python
try:
    # Business logic
    return success_response
except SpecificException as e:
    print(f"Error context: {e}")  # Log with context
    return {
        'statusCode': 500,
        'body': json.dumps({'error': 'Descriptive user-facing message'})
    }
```

**Guidelines:**
- Use appropriate HTTP status codes (200, 400, 403, 404, 500)
- Log errors with context
- Return user-friendly error messages
- Never expose sensitive data in error messages

### 7. Code Review Checks

Before completing any task, verify:

- [ ] Lambda has proper error handling with try/except
- [ ] Authentication/authorization is implemented if needed
- [ ] Input validation is comprehensive
- [ ] DynamoDB Decimals are normalized in responses
- [ ] AWS operations (DynamoDB, S3) have error handling
- [ ] Configuration values are defined at top of file
- [ ] No sensitive data is logged
- [ ] Proper HTTP status codes are used (200, 400, 403, 404, 500)

## Best Practices

**Code Organization:**
- Keep Lambdas focused and single-purpose
- Use Lambda layers for code shared across multiple Lambdas
- Group related Lambdas by domain

**Data Handling:**
- Include timestamps in created/updated records
- Use UTC timezone for all timestamps (`datetime.now(timezone.utc)`)
- Normalize DynamoDB Decimals before returning JSON

**Security:**
- Validate all input
- Use authentication decorators
- Don't log sensitive data
- Sanitize user input before database operations

**Error Handling:**
- Always use try/except blocks
- Log errors with context
- Return descriptive error messages
- Use appropriate status codes

## When Making Changes

1. **Before adding new Lambdas:** Follow the existing directory structure and patterns
2. **Before modifying auth:** Ensure `@require_role` decorator is preserved where needed
3. **After adding shared code:** Consider if it belongs in a Lambda layer
4. **After any changes:** Run through the code review checklist above
