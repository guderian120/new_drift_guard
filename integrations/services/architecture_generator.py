from typing import Dict, Any
import logging
import os

logger = logging.getLogger(__name__)


class ArchitectureGenerator:
    """Generate Mermaid architecture diagrams using AI analysis"""
    
    def __init__(self, gemini_api_key: str = None):
        """
        Initialize architecture generator with Gemini API
        
        Args:
            gemini_api_key: Gemini API key for AI analysis
        """
        self.gemini_api_key = gemini_api_key
        
    def generate_diagram(self, infrastructure: Dict[str, Any], provider: str, iac_files_content: str = None) -> str:
        """
        Generate Mermaid diagram using AI analysis
        
        Args:
            infrastructure: Parsed infrastructure resources (fallback)
            provider: Cloud provider ('AWS', 'GCP', 'Azure')
            iac_files_content: Raw IaC file content for AI analysis
            
        Returns:
            Mermaid diagram as string
        """
        # Try AI-powered generation first
        if self.gemini_api_key and iac_files_content:
            try:
                return self._generate_with_ai(iac_files_content, provider)
            except Exception as e:
                logger.warning(f"AI diagram generation failed, falling back to basic: {e}")
        
        # Fallback to basic generation
        if provider == 'AWS':
            return self._generate_aws_diagram(infrastructure)
        elif provider == 'GCP':
            return self._generate_gcp_diagram(infrastructure)
        elif provider == 'Azure':
            return self._generate_azure_diagram(infrastructure)
        
        return "graph TB\n    NoData[No infrastructure data available]"
    
    def _generate_with_ai(self, iac_content: str, provider: str) -> str:
        """Use Gemini AI to analyze IaC and generate intelligent diagram"""
        from google import genai
        
        # Initialize client with API key
        client = genai.Client(api_key=self.gemini_api_key)
        
        prompt = f"""Analyze this {provider} infrastructure code and generate a Mermaid architecture diagram.

Infrastructure Code:
```
{iac_content[:15000]}  # Limit to avoid token limits
```

Please:
1. Understand the infrastructure components and their relationships
2. Identify the architecture pattern (3-tier, microservices, etc.)
3. Show network flow (Internet → Load Balancer → App → Database)
4. Group related resources logically
5. Show security boundaries if applicable

Generate ONLY the Mermaid diagram code (starting with 'graph TB' or 'graph LR').
Use proper Mermaid syntax with:
- Subgraphs for logical grouping (VPCs, availability zones, etc.)
- Different node shapes for different resource types
- Clear labels showing resource names and types
- Arrows showing data/network flow

Return ONLY the Mermaid code, no explanations."""

        # Generate content using the new SDK
        response = client.models.generate_content(
            model='gemini-2.0-flash-exp',
            contents=prompt
        )
        
        mermaid_code = response.text.strip()
        
        # Extract mermaid code if wrapped in code blocks
        if '```mermaid' in mermaid_code:
            mermaid_code = mermaid_code.split('```mermaid')[1].split('```')[0].strip()
        elif '```' in mermaid_code:
            mermaid_code = mermaid_code.split('```')[1].split('```')[0].strip()
        
        return mermaid_code
    
    def _generate_aws_diagram(self, infra: Dict) -> str:
        """Generate basic AWS architecture diagram (fallback)"""
        mermaid = ["graph TB"]
        
        # Add Internet Gateway
        mermaid.append("    Internet((Internet))")
        
        # Add VPCs
        vpcs = infra.get('vpcs', [])
        if not vpcs:
            mermaid.append("    NoVPC[No VPCs defined in IaC]")
            return "\n".join(mermaid)
        
        for idx, vpc in enumerate(vpcs):
            vpc_id = self._sanitize_id(vpc['name'])
            vpc_cidr = vpc.get('cidr', 'N/A')
            
            mermaid.append(f"    subgraph {vpc_id}[\"VPC: {vpc['name']}<br/>{vpc_cidr}\"]")
            
            # Add subnets within this VPC
            vpc_subnets = [s for s in infra.get('subnets', []) if vpc['name'] in str(s.get('vpc', ''))]
            
            if vpc_subnets:
                for subnet in vpc_subnets:
                    subnet_id = self._sanitize_id(subnet['name'])
                    subnet_cidr = subnet.get('cidr', 'N/A')
                    az = subnet.get('availability_zone', 'N/A')
                    
                    mermaid.append(f"        {subnet_id}[\"Subnet: {subnet['name']}<br/>{subnet_cidr}<br/>AZ: {az}\"]")
                    
                    # Add EC2 instances in this subnet
                    subnet_instances = [i for i in infra.get('ec2_instances', []) 
                                       if subnet['name'] in str(i.get('subnet', ''))]
                    
                    for instance in subnet_instances:
                        instance_id = self._sanitize_id(instance['name'])
                        instance_type = instance.get('instance_type', 'N/A')
                        
                        mermaid.append(f"        {instance_id}[\"EC2: {instance['name']}<br/>{instance_type}\"]")
                        mermaid.append(f"        {subnet_id} --> {instance_id}")
            
            mermaid.append("    end")
            
            # Connect Internet to VPC
            mermaid.append(f"    Internet --> {vpc_id}")
        
        # Add RDS instances
        for rds in infra.get('rds_instances', []):
            rds_id = self._sanitize_id(rds['name'])
            engine = rds.get('engine', 'N/A')
            instance_class = rds.get('instance_class', 'N/A')
            
            mermaid.append(f"    {rds_id}[(\"RDS: {rds['name']}<br/>{engine}<br/>{instance_class}\")]")
        
        # Add Load Balancers
        for lb in infra.get('load_balancers', []):
            lb_id = self._sanitize_id(lb['name'])
            lb_type = lb.get('type', 'application')
            
            mermaid.append(f"    {lb_id}{{{{\"Load Balancer: {lb['name']}<br/>{lb_type}\"}}}}")
            mermaid.append(f"    Internet --> {lb_id}")
        
        # Add S3 Buckets
        for s3 in infra.get('s3_buckets', []):
            s3_id = self._sanitize_id(s3['name'])
            bucket_name = s3.get('bucket', s3['name'])
            
            mermaid.append(f"    {s3_id}[/\"S3: {bucket_name}\"/]")
        
        # Add Lambda Functions
        for lambda_func in infra.get('lambda_functions', []):
            lambda_id = self._sanitize_id(lambda_func['name'])
            runtime = lambda_func.get('runtime', 'N/A')
            
            mermaid.append(f"    {lambda_id}[\"Lambda: {lambda_func['name']}<br/>{runtime}\"]")
        
        # Styling
        mermaid.append("    style Internet fill:#f9f,stroke:#333,stroke-width:2px")
        
        return "\n".join(mermaid)
    
    def _generate_gcp_diagram(self, infra: Dict) -> str:
        """Generate GCP architecture diagram (placeholder)"""
        return """graph TB
    Internet((Internet))
    GCP[GCP Infrastructure]
    Internet --> GCP
    Note[GCP diagram generation coming soon]
    style Note fill:#ff9,stroke:#333"""
    
    def _generate_azure_diagram(self, infra: Dict) -> str:
        """Generate Azure architecture diagram (placeholder)"""
        return """graph TB
    Internet((Internet))
    Azure[Azure Infrastructure]
    Internet --> Azure
    Note[Azure diagram generation coming soon]
    style Note fill:#ff9,stroke:#333"""
    
    @staticmethod
    def _sanitize_id(name: str) -> str:
        """Sanitize resource name for use as Mermaid ID"""
        # Replace invalid characters with underscores
        sanitized = name.replace('-', '_').replace('.', '_').replace(' ', '_')
        # Ensure it starts with a letter
        if sanitized and not sanitized[0].isalpha():
            sanitized = 'r_' + sanitized
        return sanitized or 'resource'
