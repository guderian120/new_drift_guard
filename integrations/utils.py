import boto3
from botocore.exceptions import ClientError

def validate_credentials(provider, access_key, secret_key):
    """
    Validates cloud credentials by attempting a lightweight API call.
    Returns (True, "Success") or (False, "Error Message").
    """
    if provider == 'AWS':
        if not access_key or not secret_key:
            return False, "AWS Access Key and Secret Key are required."
        
        try:
            # Attempt to create a session and call STS GetCallerIdentity
            # This verifies the keys are valid and have basic access.
            client = boto3.client(
                'sts',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            client.get_caller_identity()
            return True, "Credentials valid."
        except ClientError as e:
            return False, f"AWS Validation Failed: {str(e)}"
        except Exception as e:
            return False, f"Unexpected Error: {str(e)}"
            
    elif provider == 'GCP':
        # Placeholder for GCP validation
        return True, "GCP validation not yet implemented (Mock Success)."
        
    elif provider == 'Azure':
        # Placeholder for Azure validation
        return True, "Azure validation not yet implemented (Mock Success)."
        
    return False, "Unknown Provider."
