from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
import os
import logging

logger = logging.getLogger(__name__)

def check_storage_account_compliance(resource_group: str, storage_account_name: str) -> bool:
    """
    Check storage account compliance with security standards
    
    Args:
        resource_group (str): Azure resource group name
        storage_account_name (str): Storage account name to check
        
    Returns:
        bool: True if compliant, False if issues found
    """
    try:
        # Initialize the client with proper error handling
        subscription_id = os.getenv('AZURE_SUBSCRIPTION_ID')
        if not subscription_id:
            logger.error("AZURE_SUBSCRIPTION_ID environment variable not set")
            return False

        credential = DefaultAzureCredential()
        storage_client = StorageManagementClient(credential, subscription_id)

        # Get storage account properties with error handling
        storage_account = storage_client.storage_accounts.get_properties(
            resource_group_name=resource_group,
            account_name=storage_account_name
        )

        # Check compliance rules
        compliance_issues = []
        
        # 1. Check if public access is enabled
        if getattr(storage_account, 'allow_blob_public_access', True):
            compliance_issues.append("Public blob access is enabled")
        
        # 2. Check if HTTPS traffic is enforced
        if not getattr(storage_account, 'enable_https_traffic_only', False):
            compliance_issues.append("HTTPS traffic only is disabled")
        
        # 3. Check minimum TLS version
        if getattr(storage_account, 'minimum_tls_version', 'TLS1_0') != 'TLS1_2':
            compliance_issues.append("Minimum TLS version is not 1.2")

        # 4. Check if infrastructure encryption is enabled (updated approach)
        encryption = getattr(storage_account, 'encryption', None)
        if encryption:
            # Check using attribute access instead of .get()
            if not getattr(encryption, 'require_infrastructure_encryption', False):
                compliance_issues.append("Infrastructure encryption is disabled")
        else:
            compliance_issues.append("Encryption settings not available")

        if compliance_issues:
            logger.error(f"Compliance issues found for {storage_account_name}:")
            for issue in compliance_issues:
                logger.error(f" - {issue}")
            return False
        
        logger.info(f"{storage_account_name} is compliant with all checks")
        return True

    except Exception as e:
        logger.error(f"Error checking compliance: {str(e)}", exc_info=True)
        return False