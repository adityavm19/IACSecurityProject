import os
import json
import subprocess
import platform
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import argparse
import logging
import yaml
import re
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.security import SecurityCenter
import datetime
from typing import Dict, List, Optional, Union

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TerraformSecurityScanner:
    def __init__(self, tf_dir: str, output_dir: str = "scan_results"):
        """
        Initialize the security scanner with Terraform directory
        
        Args:
            tf_dir (str): Path to Terraform directory
            output_dir (str): Directory to store scan results
        """
        self.tf_dir = Path(tf_dir).absolute()
        self.output_dir = Path(output_dir).absolute()
        self.output_dir.mkdir(exist_ok=True)
        
        # Azure-specific configurations
        self.azure_subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
        self.azure_tenant_id = os.getenv("AZURE_TENANT_ID")
        
        # Tool configurations
        self.tools = {
            "checkov": {
                "cmd": "checkov",
                "azure_flags": ["--framework", "azure"],
                "output_file": self.output_dir / "checkov_results.json"
            },
            "tfsec": {
                "cmd": "tfsec",
                "azure_flags": ["--exclude-downloaded-modules"],
                "output_file": self.output_dir / "tfsec_results.json"
            }
        }
        
        # Custom rules configuration
        self.custom_rules_file = self.output_dir / "custom_rules_results.json"
        
        # Initialize Azure clients if credentials are available
        self.azure_credential = None
        self.resource_client = None
        self.security_center_client = None
        
        if self.azure_subscription_id:
            try:
                self.azure_credential = DefaultAzureCredential()
                self.resource_client = ResourceManagementClient(
                    self.azure_credential, 
                    self.azure_subscription_id
                )
                self.security_center_client = SecurityCenter(
                    self.azure_credential, 
                    self.azure_subscription_id,
                    "centralus"  # Default region, can be configured
                )
            except Exception as e:
                logger.warning(f"Failed to initialize Azure clients: {e}")

    def run_tool_scan(self, tool_name: str) -> bool:
        """
        Run a specific scanning tool (checkov or tfsec)
        
        Args:
            tool_name (str): Name of the tool to run ('checkov' or 'tfsec')
            
        Returns:
            bool: True if scan completed successfully, False otherwise
        """
        if tool_name not in self.tools:
            logger.error(f"Unsupported tool: {tool_name}")
            return False

        # Configure Checkov specifically
        if tool_name == "checkov":
            try:
                output_file = self.tools[tool_name]["output_file"]
                output_file.parent.mkdir(parents=True, exist_ok=True)
                
                cmd = [
                    os.path.join(os.getcwd(), 'venv', 'Scripts', 'checkov.cmd'),
                    "-d", str(self.tf_dir),
                    "--framework", "terraform",
                    "--output", "json",
                    "--quiet",
                    "--download-external-modules", "false",
                    "--skip-check", "CKV_AZURE_33",  # Example skip if needed
                    "--external-checks-dir", os.path.join(os.getcwd(), "custom_checks")
                ]
                
                logger.info(f"Running Checkov: {' '.join(cmd)}")
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600,  # Increased timeout
                    shell=True
                )
                
                # Write output regardless of exit code
                with open(output_file, "w") as f:
                    f.write(result.stdout)
                
                if result.returncode in [0, 1]:  # 0=success, 1=findings
                    logger.info(f"Checkov completed (exit {result.returncode})")
                    return True
                else:
                    logger.error(f"Checkov failed (exit {result.returncode}): {result.stderr}")
                    return False
                    
            except subprocess.TimeoutExpired:
                logger.error("Checkov scan timed out after 5 minutes")
                return False
            except Exception as e:
                logger.error(f"Unexpected error running Checkov: {str(e)}")
                return False
        
        # Keep existing tfsec implementation
        elif tool_name == "tfsec":
            try:
                cmd = [
                    'C:\\Users\\Aditya\\go\\bin\\tfsec.exe',
                    str(self.tf_dir),
                    "--format", "json",
                    "--out", str(self.tools[tool_name]["output_file"]),
                    "--no-colour",
                    "--soft-fail",
                    "--exclude-downloaded-modules"
                ]
                
                logger.info(f"Running tfsec scan with command: {' '.join(cmd)}")
                
                subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=300,
                    shell=True
                )
                
                if self.tools[tool_name]["output_file"].exists():
                    logger.info("tfsec scan completed successfully")
                    return True
                else:
                    logger.error("tfsec completed but no output file was created")
                    return False
                    
            except subprocess.CalledProcessError as e:
                logger.error(f"tfsec scan failed with exit code {e.returncode}")
                logger.debug(f"Command output:\nSTDOUT: {e.stdout}\nSTDERR: {e.stderr}")
                return False
            except Exception as e:
                logger.error(f"Unexpected error running tfsec: {str(e)}")
                return False

    def run_custom_scans(self) -> Dict:
        """
        Run custom security scans that aren't covered by checkov or tfsec
        
        Returns:
            Dict: Results of custom scans
        """
        custom_results = {
            "metadata": {
                "scan_type": "custom_rules",
                "directory": str(self.tf_dir)
            },
            "results": [],
            "summary": {
                "total_checks": 0,
                "failures": 0,
                "warnings": 0
            }
        }
        
        # Get all Terraform files
        tf_files = list(self.tf_dir.glob("*.tf")) + list(self.tf_dir.glob("*.tfvars"))
        
        if not tf_files:
            logger.warning("No Terraform files found in directory")
            return custom_results
        
        # Custom Rule 1: Check for hardcoded secrets
        self._check_hardcoded_secrets(tf_files, custom_results)
        
        # Custom Rule 2: Check for overly permissive network rules
        self._check_permissive_network_rules(tf_files, custom_results)
        
        # Custom Rule 3: Validate Azure resource naming conventions
        self._validate_azure_naming_conventions(tf_files, custom_results)
        
        # Custom Rule 4: Check for missing resource tags
        self._check_missing_tags(tf_files, custom_results)
        
        # Custom Rule 5: Validate Azure region usage
        self._validate_azure_regions(tf_files, custom_results)
        
        # Custom Rule 6: Ensure Azure Storage Accounts do not allow public access
        self._check_storage_account_public_access(tf_files, custom_results)
        
        # Custom Rule 7: Ensure secrets are stored in Azure Key Vault
        self._check_secure_storage_for_secrets(tf_files, custom_results)
        
        # Custom Rule 8: Ensure VMs are using Managed Disks
        self._check_managed_disks(tf_files, custom_results)
        
        # Custom Rule 9: Ensure VNet Isolation for sensitive resources
        self._check_virtual_network_isolation(tf_files, custom_results)
        
        # Custom Rule 10: Enforce strict Azure Resource Group Naming Conventions
        self._validate_azure_resource_group_naming(tf_files, custom_results)
        
        # Custom Rule 11: Ensure Transparent Data Encryption (TDE) for Azure SQL Databases
        self._check_sql_database_encryption(tf_files, custom_results)
        
        # Custom Rule 12: Enforce SSL/TLS for Azure App Service
        self._check_ssl_enforced(tf_files, custom_results)
        
        # Custom Rule 13: Enforce Managed Identity for Azure Resources
        self._check_managed_identity(tf_files, custom_results)
        
        # Custom Rule 14: Prevent use of default resource names in Azure
        self._check_default_resource_names(tf_files, custom_results)
        
        # Custom Rule 15: Enable deletion protection on critical Azure resources
        self._check_deletion_protection(tf_files, custom_results)
        
        # Custom Rule 16: Prevent Public IP Assignment on Azure resources
        self._check_public_ip_assigned(tf_files, custom_results)
        
        # Custom Rule 17: Prevent use of inline IAM policies in Azure
        self._check_inline_policies(tf_files, custom_results)
        
        # Custom Rule 18: Ensure Azure resources use secure images
        #self._check_secure_vm_images(tf_files, custom_results)
        
        # Custom Rule 19: Ensure Azure resource backup configurations
        self._check_backup_configuration(tf_files, custom_results)
        
        # Custom Rule 20: Enforce strict network segmentation for Azure resources
        self._check_network_segmentation(tf_files, custom_results)
        
        # Save custom results
        with open(self.custom_rules_file, "w") as f:
            json.dump(custom_results, f, indent=2)
            
        return custom_results

    def _check_hardcoded_secrets(self, tf_files: List[Path], results: Dict):
        """
        Custom check for hardcoded secrets in Terraform files
        
        Args:
            tf_files (List[Path]): List of Terraform files to scan
            results (Dict): Results dictionary to update
        """
        secret_patterns = [
            r"(password|pwd|secret|key|token)\s*=\s*[\"'].+?[\"']",
            r"client_secret\s*=\s*[\"'].+?[\"']",
            r"connection_string\s*=\s*[\"'].+?[\"']"
        ]
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                for pattern in secret_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        results["results"].append({
                            "rule_id": "CUSTOM001",
                            "severity": "HIGH",
                            "file_path": str(tf_file),
                            "line_number": self._get_line_number(content, match.start()),
                            "description": "Hardcoded secret detected",
                            "details": f"Potential hardcoded secret: {match.group(0)}",
                            "remediation": "Use Azure Key Vault for secret management"
                        })
                        results["summary"]["failures"] += 1
                        results["summary"]["total_checks"] += 1

    def _check_permissive_network_rules(self, tf_files: List[Path], results: Dict):
        """
        Check for overly permissive network security rules
        
        Args:
            tf_files (List[Path]): List of Terraform files to scan
            results (Dict): Results dictionary to update
        """
        permissive_patterns = [
            (r"source_address_prefix\s*=\s*[\"']\*[\"']", "Allow all source IPs"),
            (r"destination_address_prefix\s*=\s*[\"']\*[\"']", "Allow all destination IPs"),
            (r"access\s*=\s*[\"']Allow[\"']\s*.*\s*direction\s*=\s*[\"']Inbound[\"']", "Permissive inbound rule"),
            (r"ports\s*=\s*[\"']\*[\"']", "All ports open")
        ]
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                for pattern, description in permissive_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        results["results"].append({
                            "rule_id": "CUSTOM002",
                            "severity": "HIGH",
                            "file_path": str(tf_file),
                            "line_number": self._get_line_number(content, match.start()),
                            "description": "Overly permissive network rule",
                            "details": description,
                            "remediation": "Implement least privilege network rules"
                        })
                        results["summary"]["failures"] += 1
                        results["summary"]["total_checks"] += 1

    def _validate_azure_naming_conventions(self, tf_files: List[Path], results: Dict):
        """
        Validate Azure resource naming conventions
        
        Args:
            tf_files (List[Path]): List of Terraform files to scan
            results (Dict): Results dictionary to update
        """
        naming_patterns = {
            "resource_group": r"^rg-[a-z0-9-]{1,90}$",
            "storage_account": r"^st[a-z0-9]{1,24}$",
            "virtual_network": r"^vnet-[a-z0-9-]{1,80}$",
            "subnet": r"^snet-[a-z0-9-]{1,80}$"
        }
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                for resource_type, pattern in naming_patterns.items():
                    # Look for resource definitions with names
                    resource_matches = re.finditer(
                        rf"resource\s+\"azurerm_{resource_type}\"\s+\"[^\"]+\"\s*{{.*?name\s*=\s*\"([^\"]+)\"",
                        content,
                        re.DOTALL
                    )
                    
                    for match in resource_matches:
                        resource_name = match.group(1)
                        if not re.match(pattern, resource_name):
                            results["results"].append({
                                "rule_id": "CUSTOM003",
                                "severity": "MEDIUM",
                                "file_path": str(tf_file),
                                "line_number": self._get_line_number(content, match.start(1)),
                                "description": f"Invalid {resource_type} naming convention",
                                "details": f"Resource name '{resource_name}' doesn't match pattern '{pattern}'",
                                "remediation": f"Follow Azure naming conventions for {resource_type}"
                            })
                            results["summary"]["failures"] += 1
                        results["summary"]["total_checks"] += 1

    def _check_missing_tags(self, tf_files: List[Path], results: Dict):
        """
        Check for missing required tags on Azure resources
        
        Args:
            tf_files (List[Path]): List of Terraform files to scan
            results (Dict): Results dictionary to update
        """
        required_tags = ["Environment", "CostCenter", "Owner", "Project"]
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                
                # Find all Azure resources
                resource_matches = re.finditer(
                    r"resource\s+\"azurerm_[^\"]+\"\s+\"[^\"]+\"\s*({.*?})",
                    content,
                    re.DOTALL
                )
                
                for match in resource_matches:
                    resource_block = match.group(1)
                    tags_match = re.search(r"tags\s*=\s*({.*?})", resource_block, re.DOTALL)
                    
                    if not tags_match:
                        # No tags block at all
                        results["results"].append({
                            "rule_id": "CUSTOM004",
                            "severity": "MEDIUM",
                            "file_path": str(tf_file),
                            "line_number": self._get_line_number(content, match.start()),
                            "description": "Missing tags block",
                            "details": "Resource is missing a tags block entirely",
                            "remediation": "Add tags to all resources with at least: " + ", ".join(required_tags)
                        })
                        results["summary"]["failures"] += 1
                        results["summary"]["total_checks"] += 1
                        continue
                        
                    # Check for missing required tags
                    tags_content = tags_match.group(1)
                    missing_tags = []
                    for tag in required_tags:
                        if not re.search(rf"{tag}\s*=", tags_content):
                            missing_tags.append(tag)
                            
                    if missing_tags:
                        results["results"].append({
                            "rule_id": "CUSTOM004",
                            "severity": "MEDIUM",
                            "file_path": str(tf_file),
                            "line_number": self._get_line_number(content, tags_match.start()),
                            "description": "Missing required tags",
                            "details": f"Missing required tags: {', '.join(missing_tags)}",
                            "remediation": "Add all required tags to the resource"
                        })
                        results["summary"]["failures"] += 1
                    results["summary"]["total_checks"] += 1

    def _validate_azure_regions(self, tf_files: List[Path], results: Dict):
        """
        Validate that Azure regions are from an approved list
        
        Args:
            tf_files (List[Path]): List of Terraform files to scan
            results (Dict): Results dictionary to update
        """
        approved_regions = [
            "eastus", "eastus2", "westus2", "centralus",
            "northcentralus", "southcentralus", "westeurope",
            "northeurope"
        ]
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                
                # Find all location/region assignments
                location_matches = re.finditer(
                    r"(location|region)\s*=\s*\"([^\"]+)\"",
                    content,
                    re.IGNORECASE
                )
                
                for match in location_matches:
                    region = match.group(2).lower()
                    if region not in approved_regions:
                        results["results"].append({
                            "rule_id": "CUSTOM005",
                            "severity": "MEDIUM",
                            "file_path": str(tf_file),
                            "line_number": self._get_line_number(content, match.start(2)),
                            "description": "Non-approved Azure region",
                            "details": f"Region '{region}' is not in the approved list",
                            "remediation": f"Use one of the approved regions: {', '.join(approved_regions)}"
                        })
                        results["summary"]["failures"] += 1
                    results["summary"]["total_checks"] += 1

    def _check_storage_account_public_access(self, tf_files: List[Path], results: Dict):
        public_access_pattern = r"allow_blob_public_access\s*=\s*true"
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                matches = re.finditer(public_access_pattern, content, re.IGNORECASE)
                for match in matches:
                    results["results"].append({
                        "rule_id": "CUSTOM001",
                        "severity": "HIGH",
                        "file_path": str(tf_file),
                        "line_number": self._get_line_number(content, match.start()),
                        "description": "Public access allowed on Azure Storage Account",
                        "remediation": "Disable public access on Storage Account"
                    })
                    results["summary"]["failures"] += 1

    def _check_secure_storage_for_secrets(self, tf_files: List[Path], results: Dict):
        secret_patterns = [
            r"secret\s*=\s*[\"'].+?[\"']",
            r"password\s*=\s*[\"'].+?[\"']"
        ]
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                for pattern in secret_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        results["results"].append({
                            "rule_id": "CUSTOM002",
                            "severity": "HIGH",
                            "file_path": str(tf_file),
                            "line_number": self._get_line_number(content, match.start()),
                            "description": "Hardcoded secret detected",
                            "remediation": "Use Azure Key Vault for secret management"
                        })
                        results["summary"]["failures"] += 1


    def _check_managed_disks(self, tf_files: List[Path], results: Dict):
        managed_disk_pattern = r"storage_profile\s*=\s*\"Managed\""
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                matches = re.finditer(managed_disk_pattern, content, re.IGNORECASE)
                for match in matches:
                    results["results"].append({
                        "rule_id": "CUSTOM003",
                        "severity": "HIGH",
                        "file_path": str(tf_file),
                        "line_number": self._get_line_number(content, match.start()),
                        "description": "Unmanaged disk detected",
                        "remediation": "Use Azure Managed Disks for VM storage"
                    })
                    results["summary"]["failures"] += 1

    def _check_virtual_network_isolation(self, tf_files: List[Path], results: Dict):
        vnet_isolation_pattern = r"subnet\s*=\s*\"private\""
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                matches = re.finditer(vnet_isolation_pattern, content, re.IGNORECASE)
                for match in matches:
                    results["results"].append({
                        "rule_id": "CUSTOM004",
                        "severity": "HIGH",
                        "file_path": str(tf_file),
                        "line_number": self._get_line_number(content, match.start()),
                        "description": "Non-isolated subnet detected",
                        "remediation": "Ensure subnets are isolated and private"
                    })
                    results["summary"]["failures"] += 1

    def _validate_azure_resource_group_naming(self, tf_files: List[Path], results: Dict):
        naming_pattern = r"^rg-[a-z0-9-]+$"
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                resource_group_matches = re.finditer(r"resource\s*\"azurerm_resource_group\"\s*\"[^\"]+\"\s*{.*?name\s*=\s*\"([^\"]+)\"", content, re.DOTALL)
                for match in resource_group_matches:
                    resource_group_name = match.group(1)
                    if not re.match(naming_pattern, resource_group_name):
                        results["results"].append({
                            "rule_id": "CUSTOM005",
                            "severity": "MEDIUM",
                            "file_path": str(tf_file),
                            "line_number": self._get_line_number(content, match.start(1)),
                            "description": "Invalid Azure Resource Group name",
                            "remediation": "Follow naming convention: rg-{project}-{env}"
                        })
                        results["summary"]["failures"] += 1


    def _check_sql_database_encryption(self, tf_files: List[Path], results: Dict):
        encryption_pattern = r"transparent_data_encryption_enabled\s*=\s*false"
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                matches = re.finditer(encryption_pattern, content, re.IGNORECASE)
                for match in matches:
                    results["results"].append({
                        "rule_id": "CUSTOM006",
                        "severity": "HIGH",
                        "file_path": str(tf_file),
                        "line_number": self._get_line_number(content, match.start()),
                        "description": "Transparent Data Encryption (TDE) disabled on SQL Database",
                        "remediation": "Enable Transparent Data Encryption (TDE) on Azure SQL Database"
                    })
                    results["summary"]["failures"] += 1

    def _check_azure_region_compliance(self, tf_files: List[Path], results: Dict):
        approved_regions = ["eastus", "westeurope", "centralus"]
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                region_matches = re.finditer(r"location\s*=\s*\"([^\"]+)\"", content)
                for match in region_matches:
                    region = match.group(1).lower()
                    if region not in approved_regions:
                        results["results"].append({
                            "rule_id": "CUSTOM007",
                            "severity": "HIGH",
                            "file_path": str(tf_file),
                            "line_number": self._get_line_number(content, match.start(1)),
                            "description": "Resource created in non-compliant Azure region",
                            "remediation": f"Use approved regions: {', '.join(approved_regions)}"
                        })
                        results["summary"]["failures"] += 1


    def _check_ssl_enforced(self, tf_files: List[Path], results: Dict):
        ssl_pattern = r"ssl_enabled\s*=\s*false"
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                matches = re.finditer(ssl_pattern, content, re.IGNORECASE)
                for match in matches:
                    results["results"].append({
                        "rule_id": "CUSTOM008",
                        "severity": "HIGH",
                        "file_path": str(tf_file),
                        "line_number": self._get_line_number(content, match.start()),
                        "description": "SSL/TLS is not enforced on Azure App Service",
                        "remediation": "Enable SSL/TLS for Azure App Service"
                    })
                    results["summary"]["failures"] += 1


    def _check_managed_identity(self, tf_files: List[Path], results: Dict):
        identity_pattern = r"managed_identity_type\s*=\s*\"None\""
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                matches = re.finditer(identity_pattern, content, re.IGNORECASE)
                for match in matches:
                    results["results"].append({
                        "rule_id": "CUSTOM009",
                        "severity": "HIGH",
                        "file_path": str(tf_file),
                        "line_number": self._get_line_number(content, match.start()),
                        "description": "Managed Identity not used for Azure resource",
                        "remediation": "Enable Managed Identity for Azure resources"
                    })
                    results["summary"]["failures"] += 1


    def _check_default_resource_names(self, tf_files: List[Path], results: Dict):
        default_pattern = r"name\s*=\s*\"default\""
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                matches = re.finditer(default_pattern, content, re.IGNORECASE)
                for match in matches:
                    results["results"].append({
                        "rule_id": "CUSTOM010",
                        "severity": "MEDIUM",
                        "file_path": str(tf_file),
                        "line_number": self._get_line_number(content, match.start()),
                        "description": "Default resource name used",
                        "remediation": "Use descriptive, unique names for resources"
                    })
                    results["summary"]["failures"] += 1


    def _check_deletion_protection(self, tf_files: List[Path], results: Dict):
        protection_pattern = r"deletion_protection\s*=\s*false"
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                matches = re.finditer(protection_pattern, content, re.IGNORECASE)
                for match in matches:
                    results["results"].append({
                        "rule_id": "CUSTOM011",
                        "severity": "HIGH",
                        "file_path": str(tf_file),
                        "line_number": self._get_line_number(content, match.start()),
                        "description": "Deletion protection disabled for Azure resource",
                        "remediation": "Enable deletion protection for critical resources"
                    })
                    results["summary"]["failures"] += 1

    def _check_public_ip_assigned(self, tf_files: List[Path], results: Dict):
        public_ip_pattern = r"public_ip\s*=\s*true"
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                matches = re.finditer(public_ip_pattern, content, re.IGNORECASE)
                for match in matches:
                    results["results"].append({
                        "rule_id": "CUSTOM016",
                        "severity": "HIGH",
                        "file_path": str(tf_file),
                        "line_number": self._get_line_number(content, match.start()),
                        "description": "Public IP assigned to Azure resource",
                        "remediation": "Use private IP addresses and secure access methods for sensitive resources"
                    })
                    results["summary"]["failures"] += 1
        
    
    def _check_inline_policies(self, tf_files: List[Path], results: Dict):
        inline_policy_pattern = r"inline_policy\s*=\s*true"
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                matches = re.finditer(inline_policy_pattern, content, re.IGNORECASE)
                for match in matches:
                    results["results"].append({
                        "rule_id": "CUSTOM017",
                        "severity": "MEDIUM",
                        "file_path": str(tf_file),
                        "line_number": self._get_line_number(content, match.start()),
                        "description": "Inline IAM policy used",
                        "remediation": "Use managed IAM policies instead of inline policies"
                    })
                    results["summary"]["failures"] += 1

    
    def _check_vm_image_security(self, tf_files: List[Path], results: Dict):
        insecure_image_patterns = [
            r"image\s*=\s*\"(ubuntu|centos|debian|windows)_latest\"",
            r"image\s*=\s*\"[^\"]+\".*\s*version\s*=\s*\"latest\""
        ]
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                for pattern in insecure_image_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        results["results"].append({
                            "rule_id": "CUSTOM018",
                            "severity": "HIGH",
                            "file_path": str(tf_file),
                            "line_number": self._get_line_number(content, match.start()),
                            "description": "Insecure VM image detected",
                            "remediation": "Use a secure, custom image or a vetted, supported image"
                        })
                        results["summary"]["failures"] += 1


    def _check_backup_configuration(self, tf_files: List[Path], results: Dict):
        backup_pattern = r"backup_enabled\s*=\s*false"
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                matches = re.finditer(backup_pattern, content, re.IGNORECASE)
                for match in matches:
                    results["results"].append({
                        "rule_id": "CUSTOM019",
                        "severity": "HIGH",
                        "file_path": str(tf_file),
                        "line_number": self._get_line_number(content, match.start()),
                        "description": "Backup configuration is disabled for critical Azure resource",
                        "remediation": "Enable backup for critical resources like Azure SQL, Storage Accounts"
                    })
                    results["summary"]["failures"] += 1


    def _check_network_segmentation(self, tf_files: List[Path], results: Dict):
        vnet_pattern = r"vnet\s*=\s*\"[^\"]+\""
        nsg_pattern = r"nsg\s*=\s*\"[^\"]+\""
        open_ports_pattern = r"ports\s*=\s*\[\"*\*\"]"  # Allow all ports
        
        for tf_file in tf_files:
            with open(tf_file, "r") as f:
                content = f.read()
                # Check for non-isolated VNets
                matches = re.finditer(vnet_pattern, content, re.IGNORECASE)
                for match in matches:
                    results["results"].append({
                        "rule_id": "CUSTOM020",
                        "severity": "HIGH",
                        "file_path": str(tf_file),
                        "line_number": self._get_line_number(content, match.start()),
                        "description": "Non-isolated VNet detected",
                        "remediation": "Ensure sensitive resources are deployed in isolated VNets"
                    })
                    results["summary"]["failures"] += 1

                # Check for open ports in NSGs
                matches = re.finditer(nsg_pattern, content, re.IGNORECASE)
                for match in matches:
                    if re.search(open_ports_pattern, content):
                        results["results"].append({
                            "rule_id": "CUSTOM021",
                            "severity": "HIGH",
                            "file_path": str(tf_file),
                            "line_number": self._get_line_number(content, match.start()),
                            "description": "Overly permissive NSG rule detected",
                            "remediation": "Use least-privilege access rules in Network Security Groups"
                        })
                        results["summary"]["failures"] += 1







    def _get_line_number(self, content: str, position: int) -> int:
        """
        Get line number from content and character position
        
        Args:
            content (str): Full content of the file
            position (int): Character position in content
            
        Returns:
            int: Line number (1-based)
        """
        return content[:position].count('\n') + 1

    
    def generate_report(self) -> Path:
        """Generate consolidated security report with enhanced error handling"""
        report = {
            "metadata": {
                "terraform_directory": str(self.tf_dir),
                "scan_timestamp": datetime.datetime.now().isoformat(),
                "azure_subscription": self.azure_subscription_id or "Not configured"
            },
            "scans": {},
            "summary": {
                "total_findings": 0,
                "critical_findings": 0,
                "high_findings": 0,
                "medium_findings": 0,
                "low_findings": 0,
                "scan_errors": []  # Track any scan processing errors
            }
        }

        def safe_json_load(file_path: Path) -> Optional[Union[Dict, List]]:
            """Safely load JSON file with comprehensive error handling"""
            try:
                with open(file_path, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in {file_path}: {str(e)}")
                report["summary"]["scan_errors"].append(f"Invalid JSON in {file_path.name}")
                return None
            except Exception as e:
                logger.error(f"Failed to load {file_path}: {str(e)}")
                report["summary"]["scan_errors"].append(f"Failed to load {file_path.name}")
                return None

        # Process each scan tool's results
        for tool in ["checkov", "tfsec", "custom_rules"]:
            file_path = getattr(self, f"{tool}_results_file", self.output_dir / f"{tool}_results.json")
            
            if file_path.exists():
                results = safe_json_load(file_path)
                if results is not None:
                    report["scans"][tool] = results
                    try:
                        self._update_summary(report["summary"], tool, results)
                    except Exception as e:
                        logger.error(f"Error processing {tool} results: {str(e)}")
                        report["summary"]["scan_errors"].append(f"Error processing {tool} results")

        


        # Save final report
        report_file = self.output_dir / "security_report.json"
        try:
            with open(report_file, "w") as f:
                json.dump(report, f, indent=2)
            logger.info(f"Security report generated at {report_file}")
        except Exception as e:
            logger.error(f"Failed to save report: {str(e)}")
            raise RuntimeError(f"Could not save security report: {str(e)}")

        return report_file

    def _update_summary(self, summary: Dict, tool: str, results: Union[Dict, List]) -> None:
        """Safely update summary with findings from a specific tool"""
        try:
            if tool == "checkov":
                if isinstance(results, dict):
                    failed_checks = results.get("results", {}).get("failed_checks", [])
                    if not isinstance(failed_checks, list):
                        logger.warning(f"Unexpected checkov results format: {type(failed_checks)}")
                        return
                    
                    summary["total_findings"] += len(failed_checks)
                    for check in failed_checks:
                        severity = str(check.get("severity", "")).strip().upper()
                        if severity == "CRITICAL":
                            summary["critical_findings"] += 1
                        elif severity == "HIGH":
                            summary["high_findings"] += 1
                        elif severity == "MEDIUM":
                            summary["medium_findings"] += 1
                        elif severity == "LOW":
                            summary["low_findings"] += 1

            elif tool == "tfsec":
                if not isinstance(results, list):
                    logger.warning(f"Unexpected tfsec results format: {type(results)}")
                    return
                    
                summary["total_findings"] += len(results)
                for result in results:
                    if not isinstance(result, dict):
                        continue
                    severity = str(result.get("severity", "")).strip().upper()
                    if severity == "CRITICAL":
                        summary["critical_findings"] += 1
                    elif severity == "HIGH":
                        summary["high_findings"] += 1
                    elif severity == "MEDIUM":
                        summary["medium_findings"] += 1
                    elif severity == "LOW":
                        summary["low_findings"] += 1

            elif tool == "custom_rules":
                if not isinstance(results, dict):
                    logger.warning(f"Unexpected custom rules format: {type(results)}")
                    return
                    
                failures = results.get("summary", {}).get("failures", 0)
                try:
                    summary["total_findings"] += int(failures)
                except (ValueError, TypeError):
                    logger.warning(f"Invalid failures count: {failures}")
                
                # Process custom rule severities if available
                for result in results.get("results", []):
                    if isinstance(result, dict):
                        severity = str(result.get("severity", "")).strip().upper()
                        if severity == "CRITICAL":
                            summary["critical_findings"] += 1
                        elif severity == "HIGH":
                            summary["high_findings"] += 1
                        elif severity == "MEDIUM":
                            summary["medium_findings"] += 1
                        elif severity == "LOW":
                            summary["low_findings"] += 1

        except Exception as e:
            logger.error(f"Unexpected error in _update_summary: {str(e)}")
            raise

    def parse_scan_results(self):
        """
        Parse the results of all scans (Checkov, tfsec, custom rules) into a structured format.
        
        Returns:
            dict: A dictionary with scan tool names as keys and their issues as values.
        """
        scan_results = {}
        
        # Parse Checkov results
        checkov_results = self.load_results("checkov_results.json")
        scan_results["Checkov"] = self.extract_issues(checkov_results)
        
        # Parse tfsec results
        tfsec_results = self.load_results("tfsec_results.json")
        scan_results["tfsec"] = self.extract_issues(tfsec_results)
        
        # Parse custom rules results
        custom_results = self.load_results("custom_rules_results.json")
        scan_results["Custom Rules"] = self.extract_issues(custom_results)
        
        return scan_results

    def load_results(self, file_name):
        try:
            with open(file_name, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading results from {file_name}: {str(e)}")
            return {}

    def extract_issues(self, results):
        issues = []
        for result in results.get("results", []):
            issues.append({
                "severity": result.get("severity", "UNKNOWN"),
                "description": result.get("description", "No description")
            })
        return issues


    def run_all_scans(self) -> bool:
        """
        Run all security scans and generate final report
        
        Returns:
            bool: True if all scans completed successfully, False otherwise
        """
        success = True
        
        # Run standard tools
        for tool in self.tools.keys():
            if not self.run_tool_scan(tool):
                success = False
                
        # Run custom scans
        self.run_custom_scans()
        
        # Generate final report
        #self.generate_report()

        #scan_results = self.parse_scan_results()  # This will now parse Checkov, tfsec, and custom rule results
    
        # Display summary of findings in a structured format
        #self.display_scan_summary(scan_results)
            
        
        return success

