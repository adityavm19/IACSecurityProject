import subprocess
import os
import json

def get_terraform_path():
    # Try multiple possible locations
    possible_paths = [
        "C:\\ProgramData\\chocolatey\\bin\\terraform.exe",
        os.path.join(os.getcwd(), 'venv', 'Scripts', 'terraform.exe'),
        'terraform'  # Try PATH
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    raise FileNotFoundError("Could not find Terraform executable")

def run_terraform_command(template, command, args=None):
    terraform_path = get_terraform_path()
    template_dir = os.path.join("terraform", template)
    original_dir = os.getcwd()

    try:
        os.chdir(template_dir)
        
        cmd = [terraform_path, command]
        if args:
            cmd.extend(args)
            
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        print("\n--- Terraform Output ---")
        print(result.stdout)
        if result.stderr:
            print("\n--- Terraform Error ---")
            print(result.stderr)

        if result.returncode != 0:
            raise Exception(f"Terraform {command} failed!")

        print(f"✅ Terraform {command} completed successfully.")
        return result.stdout

    finally:
        os.chdir(original_dir)

def run_terraform_plan(template):
    print(f"Running terraform plan for {template}...")
    return run_terraform_command(template, "plan")

def run_terraform_apply(template):
    print(f"Running terraform apply for {template}...")
    return run_terraform_command(template, "apply", ["-auto-approve"])

def get_terraform_output(template, output_name):
    output = run_terraform_command(template, "output", ["-json"])
    outputs = json.loads(output)
    return outputs.get(output_name, {}).get("value")