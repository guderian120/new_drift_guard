import os
import tempfile
import shutil
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging

try:
    import hcl2
    import git
except ImportError as e:
    raise ImportError(
        "Required packages not installed. Run: pip install python-hcl2 GitPython"
    ) from e

logger = logging.getLogger(__name__)


class TerraformParser:
    """Service to parse Terraform files and extract expected infrastructure state"""
    
    def __init__(self, repo_url: str, repo_token: Optional[str] = None):
        """
        Initialize Terraform parser
        
        Args:
            repo_url: Git repository URL (HTTPS or SSH)
            repo_token: Optional personal access token for private repositories
        """
        self.repo_url = repo_url
        self.repo_token = repo_token
        self.temp_dir = None
        
    def clone_repository(self) -> Path:
        """
        Clone the Git repository to a temporary directory
        
        Returns:
            Path to the cloned repository
        """
        self.temp_dir = tempfile.mkdtemp(prefix='driftguard_')
        logger.info(f"Cloning repository {self.repo_url} to {self.temp_dir}")
        
        try:
            # If token is provided, inject it into the URL
            clone_url = self.repo_url
            if self.repo_token and self.repo_url.startswith('https://'):
                # Format: https://token@github.com/user/repo.git
                clone_url = self.repo_url.replace('https://', f'https://{self.repo_token}@')
            
            git.Repo.clone_from(clone_url, self.temp_dir, depth=1)
            logger.info("Repository cloned successfully")
            return Path(self.temp_dir)
            
        except Exception as e:
            logger.error(f"Failed to clone repository: {str(e)}")
            self.cleanup()
            raise
    
    def parse_terraform_files(self, repo_path: Path) -> Dict[str, Any]:
        """
        Parse all .tf files in the repository
        
        Args:
            repo_path: Path to the cloned repository
            
        Returns:
            Dictionary with parsed Terraform configuration
        """
        terraform_config = {
            'resources': [],
            'variables': {},
            'outputs': {}
        }
        
        # Find all .tf files recursively
        tf_files = list(repo_path.rglob('*.tf'))
        logger.info(f"Found {len(tf_files)} Terraform files")
        
        successful_parses = 0
        failed_parses = 0
        
        for tf_file in tf_files:
            try:
                with open(tf_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # Skip empty files
                    if not content.strip():
                        continue
                    
                    try:
                        parsed = hcl2.loads(content)
                    except Exception as parse_error:
                        # Log parsing error but continue with other files
                        logger.warning(f"Failed to parse {tf_file.relative_to(repo_path)}: {str(parse_error)}")
                        failed_parses += 1
                        continue
                    
                    # Extract resources - handle both dict and list formats
                    if 'resource' in parsed:
                        resource_data = parsed['resource']
                        
                        # Handle if resource is a list (some HCL parsers return lists)
                        if isinstance(resource_data, list):
                            for item in resource_data:
                                if isinstance(item, dict):
                                    for resource_type, resources in item.items():
                                        if isinstance(resources, dict):
                                            for resource_name, resource_config in resources.items():
                                                terraform_config['resources'].append({
                                                    'type': resource_type,
                                                    'name': resource_name,
                                                    'config': resource_config if isinstance(resource_config, dict) else {},
                                                    'file': str(tf_file.relative_to(repo_path))
                                                })
                        # Handle standard dict format
                        elif isinstance(resource_data, dict):
                            for resource_type, resources in resource_data.items():
                                if isinstance(resources, dict):
                                    for resource_name, resource_config in resources.items():
                                        # Handle list of configs
                                        if isinstance(resource_config, list) and resource_config:
                                            resource_config = resource_config[0] if isinstance(resource_config[0], dict) else {}
                                        elif not isinstance(resource_config, dict):
                                            resource_config = {}
                                        
                                        terraform_config['resources'].append({
                                            'type': resource_type,
                                            'name': resource_name,
                                            'config': resource_config,
                                            'file': str(tf_file.relative_to(repo_path))
                                        })
                    
                    # Extract variables - with error handling
                    if 'variable' in parsed:
                        var_data = parsed['variable']
                        if isinstance(var_data, dict):
                            terraform_config['variables'].update(var_data)
                        elif isinstance(var_data, list):
                            for item in var_data:
                                if isinstance(item, dict):
                                    terraform_config['variables'].update(item)
                    
                    # Extract outputs - with error handling
                    if 'output' in parsed:
                        output_data = parsed['output']
                        if isinstance(output_data, dict):
                            terraform_config['outputs'].update(output_data)
                        elif isinstance(output_data, list):
                            for item in output_data:
                                if isinstance(item, dict):
                                    terraform_config['outputs'].update(item)
                    
                    successful_parses += 1
                        
            except Exception as e:
                logger.warning(f"Error processing {tf_file.relative_to(repo_path)}: {str(e)}")
                failed_parses += 1
                continue
        
        logger.info(f"Successfully parsed {successful_parses}/{len(tf_files)} Terraform files")
        logger.info(f"Extracted {len(terraform_config['resources'])} resources")
        
        if failed_parses > 0:
            logger.warning(f"Failed to parse {failed_parses} files - these will be skipped")
        
        return terraform_config
    
    def extract_aws_resources(self, terraform_config: Dict[str, Any]) -> Dict[str, List[Dict]]:
        """
        Extract AWS resources from parsed Terraform configuration
        
        Args:
            terraform_config: Parsed Terraform configuration
            
        Returns:
            Dictionary mapping resource types to resource definitions
        """
        aws_resources = {
            'ec2_instances': [],
            's3_buckets': [],
            'security_groups': [],
            'rds_instances': []
        }
        
        for resource in terraform_config['resources']:
            resource_type = resource['type']
            resource_name = resource['name']
            config = resource['config']
            
            # EC2 Instances
            if resource_type == 'aws_instance':
                aws_resources['ec2_instances'].append({
                    'name': resource_name,
                    'instance_type': config.get('instance_type'),
                    'ami': config.get('ami'),
                    'tags': config.get('tags', {}),
                    'vpc_security_group_ids': config.get('vpc_security_group_ids', []),
                    'subnet_id': config.get('subnet_id'),
                    'config': config
                })
            
            # S3 Buckets
            elif resource_type == 'aws_s3_bucket':
                aws_resources['s3_buckets'].append({
                    'name': resource_name,
                    'bucket': config.get('bucket'),
                    'tags': config.get('tags', {}),
                    'config': config
                })
            
            # Security Groups
            elif resource_type == 'aws_security_group':
                aws_resources['security_groups'].append({
                    'name': resource_name,
                    'group_name': config.get('name'),
                    'description': config.get('description'),
                    'vpc_id': config.get('vpc_id'),
                    'ingress': config.get('ingress', []),
                    'egress': config.get('egress', []),
                    'tags': config.get('tags', {}),
                    'config': config
                })
            
            # RDS Instances
            elif resource_type == 'aws_db_instance':
                aws_resources['rds_instances'].append({
                    'name': resource_name,
                    'identifier': config.get('identifier'),
                    'engine': config.get('engine'),
                    'instance_class': config.get('instance_class'),
                    'allocated_storage': config.get('allocated_storage'),
                    'publicly_accessible': config.get('publicly_accessible', False),
                    'backup_retention_period': config.get('backup_retention_period', 0),
                    'tags': config.get('tags', {}),
                    'config': config
                })
        
        return aws_resources
    
    def parse_repository(self) -> Dict[str, List[Dict]]:
        """
        Main method to clone repository, parse Terraform files, and extract AWS resources
        
        Returns:
            Dictionary of AWS resources by type
        """
        try:
            # Clone repository
            repo_path = self.clone_repository()
            
            # Parse Terraform files
            terraform_config = self.parse_terraform_files(repo_path)
            
            # Extract AWS resources
            aws_resources = self.extract_aws_resources(terraform_config)
            
            return aws_resources
            
        finally:
            # Always cleanup temporary directory
            self.cleanup()
    
    def cleanup(self):
        """Remove temporary directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                # On Windows, Git files can be read-only, so we need to handle permissions
                def handle_remove_readonly(func, path, exc):
                    """Error handler for Windows readonly files"""
                    import stat
                    if not os.access(path, os.W_OK):
                        os.chmod(path, stat.S_IWUSR)
                        func(path)
                    else:
                        raise
                
                shutil.rmtree(self.temp_dir, onerror=handle_remove_readonly)
                logger.info(f"Cleaned up temporary directory {self.temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup {self.temp_dir}: {str(e)}")
