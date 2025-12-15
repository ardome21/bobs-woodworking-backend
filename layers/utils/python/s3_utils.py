import boto3

s3 = boto3.client('s3')

def generate_presigned_url(s3_bucket,s3_key: str, expiration=3600) -> str:
    """
    Create a URL that temporarily allows access to private S3 Object
    
    :param s3_bucket: Description
    :param s3_key: Description
    :type s3_key: str
    :param expiration: Description
    :return: Description
    :rtype: str
    
    """
    return s3.generate_presigned_url(
        ClientMethod='get_object',
        Params={
            'Bucket': s3_bucket,
            'Key': s3_key,
        },
        ExpiresIn=expiration,
    )
