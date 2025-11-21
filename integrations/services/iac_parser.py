import os
import json
import yaml
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

# Try to import hcl2, but don't fail if not available
try:
    import hcl2
    HCL2_AVAILABLE = True
except ImportError:
    HCL2_AVAILABLE = False
    logger.warning("python-hcl2 not installed. Terraform parsing will be limited.")


class IaCParser:
    """Parse Infrastructure as Code files and extract resources"""
    
    def __init__(self, repo_path: str, iac_tool: str = 'terraform'):
        """
        Initialize IaC parser
        
        Args:
            repo_path: Path to cloned repository
            iac_tool: Type of IaC tool ('terraform', 'cloudformation', 'pulumi')
        """
        self.repo_path = repo_path
        self.iac_tool = iac_tool.lower()
        
    def parse_infrastructure(self) -> Dict[str, Any]:
        """
        Parse IaC files and return infrastructure structure
        
        Returns:
            Dictionary containing parsed resources
        """
        if self.iac_tool == 'terraform':
            return self._parse_terraform()
        elif self.iac_tool == 'cloudformation':
            return self._parse_cloudformation()
        elif self.iac_tool == 'pulumi':
            return self._parse_pulumi()
        
        logger.warning(f"Unsupported IaC tool: {self.iac_tool}")
        return self._get_empty_infrastructure()
    
    def _get_empty_infrastructure(self) -> Dict[str, Any]:
        """Return empty infrastructure structure"""
        return {
            'vpcs': [],
            'subnets': [],
            'ec2_instances': [],
            'rds_instances': [],
            'load_balancers': [],
            'security_groups': [],
            's3_buckets': [],
            'lambda_functions': []
        }
    
    def _parse_terraform(self) -> Dict[str, Any]:
        """Parse Terraform .tf files"""
        if not HCL2_AVAILABLE:
            logger.error("python-hcl2 not available. Cannot parse Terraform files.")
            return self._get_empty_infrastructure()
        
        resources = self._get_empty_infrastructure()
        
        # Find all .tf files
        tf_files = []
        for root, dirs, files in os.walk(self.repo_path):
            # Skip .terraform directory
            if '.terraform' in root:
                continue
            for file in files:
                if file.endswith('.tf'):
                    tf_files.append(os.path.join(root, file))
        
        logger.info(f"Found {len(tf_files)} Terraform files")
        
        # Parse each .tf file
        for tf_file in tf_files:
            try:
                with open(tf_file, 'r', encoding='utf-8') as f:
                    tf_content = hcl2.load(f)
                
                # Extract resources
                if 'resource' in tf_content:
                    for resource_blocks in tf_content['resource']:
                        for resource_type, resource_configs in resource_blocks.items():
                            self._extract_terraform_resources(resource_type, resource_configs, resources)
            
            except Exception as e:
                logger.warning(f"Error parsing {tf_file}: {e}")
                continue
        
        logger.info(f"Parsed {len(resources['vpcs'])} VPCs, {len(resources['ec2_instances'])} EC2 instances")
        return resources
    
    def _extract_terraform_resources(self, resource_type: str, resource_configs: Dict, output: Dict):
        """Extract specific Terraform resources"""
        
        for resource_name, config in resource_configs.items():
            if resource_type == 'aws_vpc':
                output['vpcs'].append({
                    'name': resource_name,
                    'cidr': config.get('cidr_block', ['Unknown'])[0] if isinstance(config.get('cidr_block'), list) else config.get('cidr_block', 'Unknown'),
                    'tags': config.get('tags', [{}])[0] if isinstance(config.get('tags'), list) else config.get('tags', {})
                })
            
            elif resource_type == 'aws_subnet':
                output['subnets'].append({
                    'name': resource_name,
                    'cidr': config.get('cidr_block', ['Unknown'])[0] if isinstance(config.get('cidr_block'), list) else config.get('cidr_block', 'Unknown'),
                    'vpc': str(config.get('vpc_id', 'Unknown')),
                    'availability_zone': config.get('availability_zone', ['Unknown'])[0] if isinstance(config.get('availability_zone'), list) else config.get('availability_zone', 'Unknown')
                })
            
            elif resource_type == 'aws_instance':
                output['ec2_instances'].append({
                    'name': resource_name,
                    'instance_type': config.get('instance_type', ['Unknown'])[0] if isinstance(config.get('instance_type'), list) else config.get('instance_type', 'Unknown'),
                    'ami': config.get('ami', ['Unknown'])[0] if isinstance(config.get('ami'), list) else config.get('ami', 'Unknown'),
                    'subnet': str(config.get('subnet_id', 'Unknown')),
                    'security_groups': config.get('vpc_security_group_ids', [])
                })
            
            elif resource_type == 'aws_db_instance':
                output['rds_instances'].append({
                    'name': resource_name,
                    'engine': config.get('engine', ['Unknown'])[0] if isinstance(config.get('engine'), list) else config.get('engine', 'Unknown'),
                    'instance_class': config.get('instance_class', ['Unknown'])[0] if isinstance(config.get('instance_class'), list) else config.get('instance_class', 'Unknown'),
                    'allocated_storage': config.get('allocated_storage', 'Unknown')
                })
            
            elif resource_type in ['aws_lb', 'aws_alb', 'aws_elb']:
                output['load_balancers'].append({
                    'name': resource_name,
                    'type': config.get('load_balancer_type', ['application'])[0] if isinstance(config.get('load_balancer_type'), list) else config.get('load_balancer_type', 'application'),
                    'subnets': config.get('subnets', [])
                })
            
            elif resource_type == 'aws_security_group':
                output['security_groups'].append({
                    'name': resource_name,
                    'vpc': str(config.get('vpc_id', 'Unknown')),
                    'description': config.get('description', [''])[0] if isinstance(config.get('description'), list) else config.get('description', '')
                })
            
            elif resource_type == 'aws_s3_bucket':
                output['s3_buckets'].append({
                    'name': resource_name,
                    'bucket': config.get('bucket', ['Unknown'])[0] if isinstance(config.get('bucket'), list) else config.get('bucket', resource_name)
                })
            
            elif resource_type == 'aws_lambda_function':
                output['lambda_functions'].append({
                    'name': resource_name,
                    'runtime': config.get('runtime', ['Unknown'])[0] if isinstance(config.get('runtime'), list) else config.get('runtime', 'Unknown'),
                    'handler': config.get('handler', ['Unknown'])[0] if isinstance(config.get('handler'), list) else config.get('handler', 'Unknown')
                })
    
    def _parse_cloudformation(self) -> Dict[str, Any]:
        """Parse CloudFormation YAML/JSON templates"""
        resources = self._get_empty_infrastructure()
        
        # Find CloudFormation templates
        cf_files = []
        for root, dirs, files in os.walk(self.repo_path):
            for file in files:
                if file.endswith(('.yaml', '.yml', '.json')) and ('template' in file.lower() or 'stack' in file.lower()):
                    cf_files.append(os.path.join(root, file))
        
        logger.info(f"Found {len(cf_files)} CloudFormation templates")
        
        for cf_file in cf_files:
            try:
                with open(cf_file, 'r', encoding='utf-8') as f:
                    if cf_file.endswith('.json'):
                        template = json.load(f)
                    else:
                        template = yaml.safe_load(f)
                
                # Extract resources from CloudFormation template
                if 'Resources' in template:
                    for resource_name, resource_config in template['Resources'].items():
                        resource_type = resource_config.get('Type', '')
                        properties = resource_config.get('Properties', {})
                        
                        if resource_type == 'AWS::EC2::VPC':
                            resources['vpcs'].append({
                                'name': resource_name,
                                'cidr': properties.get('CidrBlock', 'Unknown'),
                                'tags': properties.get('Tags', {})
                            })
                        
                        elif resource_type == 'AWS::EC2::Instance':
                            resources['ec2_instances'].append({
                                'name': resource_name,
                                'instance_type': properties.get('InstanceType', 'Unknown'),
                                'ami': properties.get('ImageId', 'Unknown'),
                                'subnet': properties.get('SubnetId', 'Unknown')
                            })
                        
                        # Add more CloudFormation resource types as needed
            
            except Exception as e:
                logger.warning(f"Error parsing {cf_file}: {e}")
                continue
        
        return resources
    
    def _parse_pulumi(self) -> Dict[str, Any]:
        """Parse Pulumi code (placeholder)"""
        logger.info("Pulumi parsing not yet implemented")
        return self._get_empty_infrastructure()
