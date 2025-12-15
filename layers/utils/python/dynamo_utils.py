"""
DynamoDB utility functions for Lambda functions.
Provides conversion helpers for DynamoDB-specific data types.
"""
from decimal import Decimal
from typing import Any


def normalize_dynamodb_decimals(value: Any) -> Any:
    """
    Recursively convert DynamoDB Decimals to native Python types.

    This function is essential for JSON serialization of DynamoDB responses,
    as the boto3 DynamoDB client returns numeric values as Decimal objects
    which are not JSON serializable by default.

    Conversion rules:
    - Decimal values are converted to float
    - Lists are recursively processed
    - Dictionaries are recursively processed
    - All other types are returned unchanged

    Args:
        value: Any value that may contain DynamoDB Decimal objects

    Returns:
        The same structure with all Decimals converted to float

    Examples:
        >>> normalize_dynamodb_decimals(Decimal('19.99'))
        19.99

        >>> normalize_dynamodb_decimals({'price': Decimal('19.99'), 'quantity': 5})
        {'price': 19.99, 'quantity': 5}

        >>> normalize_dynamodb_decimals([Decimal('10.50'), Decimal('20.75')])
        [10.5, 20.75]
    """
    if isinstance(value, list):
        return [normalize_dynamodb_decimals(v) for v in value]
    if isinstance(value, dict):
        return {k: normalize_dynamodb_decimals(v) for k, v in value.items()}
    if isinstance(value, Decimal):
        return float(value)
    return value
