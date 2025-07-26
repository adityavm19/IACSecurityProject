import subprocess
from terraform_runner import run_terraform_plan, run_terraform_apply
from compliance_check import check_storage_account_compliance
import os
from security_scanner import TerraformSecurityScanner
from dotenv import load_dotenv
import tabulate
import argparse
import json
import logging
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
load_dotenv()   # New import



def run_pre_deployment_checks(template):
    print("🔍 Running pre-deployment security checks...")
    
    # Initialize the security scanner
    scanner = TerraformSecurityScanner(
        tf_dir=os.path.join("terraform", template),
        output_dir=os.path.join("scan_results", template)
    )
    
    # Run all scans
    if not scanner.run_all_scans():
        print("❌ Security checks failed - review findings before deployment")
        return False
    
    
    # Generate and display summary
    report_file = scanner.generate_report()
    #scan_results = scanner.parse_scan_results()
    print(f"✅ Security scan report generated at {report_file}")


    return True, report_file

def run_deployment(template):
    print("🚀 Running Terraform Apply...")
    run_terraform_apply(template)

def run_post_deployment_compliance_check(resource_group, storage_account_name):
    check_storage_account_compliance(resource_group, storage_account_name)

def parse_security_report(report_file):
    """
    Parse the security report file to extract issues and return a structured list.
    
    Args:
        report_file (str): Path to the security report file.
        
    Returns:
        list: A list of dictionaries containing tool name, severity, description, and other details.
    """
    try:
        # Load the JSON report file
        with open(report_file, "r") as f:
            report = json.load(f)

        if not isinstance(report, dict) or "scans" not in report:
            logger.error(f"Invalid structure in report file: {report_file}")
            return []

        scan_results = []

        # Parse Checkov Results
        checkov_results = report.get("scans", {}).get("checkov", {}).get("results", {}).get("failed_checks", [])
        for check in checkov_results:
            check_name = check.get("check_name", "Unknown Check")
            severity = check.get("check_result", {}).get("result", "UNKNOWN")
            file_path = check.get("file_path", "Unknown File")
            line_range = f"{check.get('file_line_range', ['Unknown', 'Unknown'])[0]}-{check.get('file_line_range', ['Unknown', 'Unknown'])[1]}"
            guideline = check.get("guideline", "No guideline provided")
            scan_results.append({
                "tool": "Checkov",
                "severity": severity,
                "description": check_name,
                "file_path": file_path,
                "line_range": line_range,
                "guideline": guideline
            })

        # Parse tfsec Results
        tfsec_results = report.get("scans", {}).get("tfsec", {}).get("results", [])
        for result in tfsec_results:
            rule_id = result.get("rule_id", "Unknown Rule")
            severity = result.get("severity", "UNKNOWN")
            description = result.get("description", "No description")
            file_path = result.get("location", {}).get("filename", "Unknown File")
            line_range = f"{result.get('location', {}).get('start_line', 'Unknown')}-{result.get('location', {}).get('end_line', 'Unknown')}"
            links = ", ".join(result.get("links", []))
            scan_results.append({
                "tool": "tfsec",
                "severity": severity,
                "description": description,
                "file_path": file_path,
                "line_range": line_range,
                "guideline": links
            })

        # Parse Custom Rules Results
        custom_results = report.get("scans", {}).get("custom_rules", {}).get("results", [])
        for custom_rule in custom_results:
            rule_id = custom_rule.get("rule_id", "Unknown Rule")
            severity = custom_rule.get("severity", "UNKNOWN")
            description = custom_rule.get("description", "No description")
            file_path = custom_rule.get("file_path", "Unknown File")
            line_number = custom_rule.get("line_number", "Unknown Line")
            remediation = custom_rule.get("remediation", "No remediation provided")
            scan_results.append({
                "tool": "Custom Rules",
                "severity": severity,
                "description": description,
                "file_path": file_path,
                "line_range": f"Line {line_number}",
                "guideline": remediation
            })

        return scan_results

    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON from {report_file}: {str(e)}")
    except Exception as e:
        logger.error(f"Error processing report file {report_file}: {str(e)}")
    
    return []  # Return an empty list in case of error




def display_summary(scan_results):
    """
    Display a summary of the scan results in a tabular format.
    
    Args:
        scan_results (list): List of dictionaries containing scan tool results.
    """
    headers = ["Tool", "Severity", "Description"]
    table = []
    
    for result in scan_results:
        table.append([result['tool'], result['severity'], result['description']])
    
    # Print the table
    print("\n🔍 Security Issues Identified:")
    print(tabulate.tabulate(table, headers, tablefmt="pretty"))

def main():
    parser = argparse.ArgumentParser(description="Run Terraform deployment with security checks.")
    parser.add_argument('--template', required=True, help="Terraform template folder name to deploy")
    parser.add_argument('--plan', action='store_true', help="Run Terraform plan and display security findings")
    parser.add_argument('--apply', action='store_true', help="Run Terraform apply after security checks")
    
    args = parser.parse_args()
    template = args.template

    try:
        # Run Pre-Deployment Checks for `--plan` mode
        if args.plan:
            success, report_file = run_pre_deployment_checks(template)
            if not success:
                print("Aborting deployment due to security issues.")
                return

            # Parse the security report and get the issues
            scan_results = parse_security_report(report_file)

            # Display the results in tabular format
            display_summary(scan_results)

        # Run Deployment for `--apply` mode
        if args.apply:
            run_deployment(template)

            # Post-Deployment Compliance Check
            print("Performing post-deployment compliance check...")
            run_post_deployment_compliance_check("example-resources", "myuniqad")

    except Exception as e:
        print(f"Deployment failed: {e}")

if __name__ == "__main__":
    main()