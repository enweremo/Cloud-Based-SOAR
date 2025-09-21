# Security Policy  

## Purpose  
This document provides guidance for protecting sensitive information in this repository and for reporting security issues responsibly.  

## Scope  
This policy applies to all code, documentation, sample data, configuration files, and build artifacts stored in this repository.  

## Reporting a Vulnerability  
- Do **not** open a public GitHub issue.  
- Use the **“Report a vulnerability”** button under the Security tab of this repository.  
- Include a clear description, reproduction steps, and relevant logs or screenshots.  
- Reports will be acknowledged promptly and fixes coordinated before public disclosure.  

## Secrets and Sensitive Data  
Do not commit any of the following:  
- AWS access keys or secret keys  
- Account numbers or ARNs tied to private resources  
- Private certificates, keys, or keystores  
- Real `.env` files or production configuration values  
- Credentials for third-party systems  

Use **placeholders** in code and documentation. Store real secrets securely in:  
- AWS Secrets Manager  
- AWS Systems Manager Parameter Store  
- GitHub Actions Secrets  

## Repository Hygiene  
1. Provide `.env.sample` to document required variables but exclude real values.  
2. Keep EC2, S3, and DynamoDB names generic in public templates.  
3. Use only safe demonstration targets such as `http://testphp.vulnweb.com`.  
4. Review commits before pushing to ensure no secrets are exposed.  
5. Enable GitHub **Secret scanning** and **Dependabot alerts**.  

## If a Secret is Accidentally Committed  
1. Remove it from history using **BFG Repo-Cleaner** or `git filter-repo`.  
2. Rotate the affected credential immediately.  
3. Record what was leaked, when it was rotated, and where the code was corrected.  

## Responsible Disclosure  
Please allow reasonable time for investigation and remediation before any public disclosure.  

## Demo Authentication Disclaimer

For demonstration purposes, this project includes a very simple static login form (HTML/PHP) hosted on an EC2 instance.  
- This is **not** intended as a production authentication system.  
- The purpose is to **simulate login attempts** (both valid and invalid) so that failures can be captured and forwarded into the SOAR workflow.  
- By intentionally keeping the login logic minimal, it provides a controlled test surface for GuardDuty, EventBridge, and the SOAR playbooks to respond to.  

**Important:** This is not a security error or misconfiguration. It is a deliberate simplification to allow repeatable demonstrations of incident detection and automated response.