import boto3
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class AWSScanner:
    """Service to scan AWS infrastructure and detect configuration drifts"""
    
    def __init__(self, access_key: str, secret_key: str, region: str = 'us-east-1'):
        """
        Initialize AWS scanner with credentials
        
        Args:
            access_key: AWS access key ID
            secret_key: AWS secret access key
            region: AWS region to scan (default: us-east-1)
        """
        self.session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        self.region = region
        
    def scan_infrastructure(self) -> List[Dict[str, Any]]:
        """
        Scan AWS infrastructure and return detected drifts
        
        Returns:
            List of drift dictionaries with resource details
        """
        drifts = []
        
        try:
            # Scan EC2 instances
            logger.info("Scanning EC2 instances...")
            drifts.extend(self._scan_ec2_instances())
        except Exception as e:
            logger.error(f"Error scanning EC2: {str(e)}")
        
        try:
            # Scan S3 buckets
            logger.info("Scanning S3 buckets...")
            drifts.extend(self._scan_s3_buckets())
        except Exception as e:
            logger.error(f"Error scanning S3: {str(e)}")
        
        try:
            # Scan Security Groups
            logger.info("Scanning Security Groups...")
            drifts.extend(self._scan_security_groups())
        except Exception as e:
            logger.error(f"Error scanning Security Groups: {str(e)}")
        
        try:
            # Scan RDS instances
            logger.info("Scanning RDS instances...")
            drifts.extend(self._scan_rds_instances())
        except Exception as e:
            logger.error(f"Error scanning RDS: {str(e)}")
        
        return drifts
    
    def _scan_ec2_instances(self) -> List[Dict]:
        """Scan EC2 instances for tag and configuration drifts"""
        ec2 = self.session.client('ec2')
        instances = ec2.describe_instances()
        
        drifts = []
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                # Skip terminated instances
                if instance['State']['Name'] == 'terminated':
                    continue
                
                drift = self._check_instance_tags(instance)
                if drift:
                    drifts.append(drift)
        
        return drifts
    
    def _check_instance_tags(self, instance: Dict) -> Optional[Dict]:
        """
        Check if instance tags match expected values
        
        Expected policy: All running instances should have:
        - Environment tag (Production, Staging, or Development)
        - Owner tag
        """
        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        instance_id = instance['InstanceId']
        
        # Check for missing Environment tag
        if 'Environment' not in tags:
            return {
                'resource_name': instance_id,
                'resource_type': 'aws_ec2_instance',
                'severity': 'high',
                'expected_state': {'tags': {'Environment': 'Required'}},
                'actual_state': {'tags': tags},
                'description': f"EC2 instance {instance_id} is missing required 'Environment' tag"
            }
        
        # Check for missing Owner tag
        if 'Owner' not in tags:
            return {
                'resource_name': instance_id,
                'resource_type': 'aws_ec2_instance',
                'severity': 'medium',
                'expected_state': {'tags': {'Owner': 'Required'}},
                'actual_state': {'tags': tags},
                'description': f"EC2 instance {instance_id} is missing required 'Owner' tag"
            }
        
        return None
    
    def _scan_s3_buckets(self) -> List[Dict]:
        """Scan S3 buckets for configuration drifts"""
        s3 = self.session.client('s3')
        
        try:
            buckets = s3.list_buckets()
        except Exception as e:
            logger.error(f"Error listing S3 buckets: {str(e)}")
            return []
        
        drifts = []
        for bucket in buckets.get('Buckets', []):
            bucket_name = bucket['Name']
            
            try:
                # Check if versioning is enabled
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get('Status') != 'Enabled':
                    drifts.append({
                        'resource_name': bucket_name,
                        'resource_type': 'aws_s3_bucket',
                        'severity': 'medium',
                        'expected_state': {'versioning': 'Enabled'},
                        'actual_state': {'versioning': versioning.get('Status', 'Disabled')},
                        'description': f"S3 bucket {bucket_name} does not have versioning enabled"
                    })
                
                # Check if encryption is enabled
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                    drifts.append({
                        'resource_name': bucket_name,
                        'resource_type': 'aws_s3_bucket',
                        'severity': 'critical',
                        'expected_state': {'encryption': 'Enabled'},
                        'actual_state': {'encryption': 'Disabled'},
                        'description': f"S3 bucket {bucket_name} does not have encryption enabled"
                    })
                    
            except Exception as e:
                logger.error(f"Error checking bucket {bucket_name}: {str(e)}")
                continue
        
        return drifts
    
    def _scan_security_groups(self) -> List[Dict]:
        """Scan Security Groups for overly permissive rules"""
        ec2 = self.session.client('ec2')
        
        try:
            security_groups = ec2.describe_security_groups()
        except Exception as e:
            logger.error(f"Error describing security groups: {str(e)}")
            return []
        
        drifts = []
        for sg in security_groups['SecurityGroups']:
            # Check for 0.0.0.0/0 ingress rules
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        drifts.append({
                            'resource_name': sg['GroupId'],
                            'resource_type': 'aws_security_group',
                            'severity': 'critical',
                            'expected_state': {'ingress': 'Restricted'},
                            'actual_state': {'ingress': '0.0.0.0/0 allowed'},
                            'description': f"Security group {sg['GroupName']} ({sg['GroupId']}) allows ingress from 0.0.0.0/0"
                        })
                        break
        
        return drifts
    
    def _scan_rds_instances(self) -> List[Dict]:
        """Scan RDS instances for configuration drifts"""
        rds = self.session.client('rds')
        
        try:
            db_instances = rds.describe_db_instances()
        except Exception as e:
            logger.error(f"Error describing RDS instances: {str(e)}")
            return []
        
        drifts = []
        for db in db_instances.get('DBInstances', []):
            db_id = db['DBInstanceIdentifier']
            
            # Check if publicly accessible
            if db.get('PubliclyAccessible', False):
                drifts.append({
                    'resource_name': db_id,
                    'resource_type': 'aws_rds_instance',
                    'severity': 'critical',
                    'expected_state': {'publicly_accessible': False},
                    'actual_state': {'publicly_accessible': True},
                    'description': f"RDS instance {db_id} is publicly accessible"
                })
            
            # Check if backup retention is enabled
            if db.get('BackupRetentionPeriod', 0) < 7:
                drifts.append({
                    'resource_name': db_id,
                    'resource_type': 'aws_rds_instance',
                    'severity': 'high',
                    'expected_state': {'backup_retention_days': '>=7'},
                    'actual_state': {'backup_retention_days': db.get('BackupRetentionPeriod', 0)},
                    'description': f"RDS instance {db_id} has insufficient backup retention ({db.get('BackupRetentionPeriod', 0)} days)"
                })
        
        return drifts
    
    def get_forensic_info(self, resource_id: str, resource_type: str) -> Dict[str, Any]:
        """
        Get forensic information from CloudTrail for a specific resource
        
        Args:
            resource_id: AWS resource ID
            resource_type: Type of resource
            
        Returns:
            Dictionary with forensic information (user, timestamp, IP, etc.)
        """
        try:
            cloudtrail = self.session.client('cloudtrail')
            
            # Query CloudTrail for events related to this resource
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=7)
            
            events = cloudtrail.lookup_events(
                LookupAttributes=[
                    {'AttributeKey': 'ResourceName', 'AttributeValue': resource_id}
                ],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=10
            )
            
            if events.get('Events'):
                latest_event = events['Events'][0]
                
                return {
                    'initiated_by_user': latest_event.get('Username', 'Unknown'),
                    'initiated_by_email': f"{latest_event.get('Username', 'unknown')}@company.com",
                    'initiated_by_role': latest_event.get('Resources', [{}])[0].get('ResourceName', 'Unknown'),
                    'change_timestamp': latest_event['EventTime'].strftime('%Y-%m-%d %H:%M:%S'),
                    'source_ip': latest_event.get('SourceIPAddress', 'Unknown'),
                    'change_method': 'console' if 'console' in latest_event.get('UserAgent', '').lower() else 'cli',
                    'user_agent': latest_event.get('UserAgent', 'Unknown'),
                    'api_calls': [
                        {
                            'timestamp': event['EventTime'].strftime('%Y-%m-%d %H:%M:%S'),
                            'api': event['EventName'],
                            'response_code': 200 if event.get('ErrorCode') is None else 400
                        }
                        for event in events['Events'][:5]
                    ],
                    'change_summary': f"Resource {resource_id} was modified via {latest_event['EventName']}",
                    'root_cause_category': 'manual_change',
                    'root_cause_analysis': f"Resource was modified by {latest_event.get('Username', 'Unknown')} using {latest_event['EventName']} API call."
                }
            
        except Exception as e:
            logger.warning(f"Could not fetch CloudTrail data for {resource_id}: {str(e)}")
        
        # Return default forensic info if CloudTrail data unavailable
        return {
            'initiated_by_user': 'Unknown',
            'change_timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            'change_method': 'unknown',
            'change_summary': 'Drift detected during infrastructure scan',
            'root_cause_category': 'unknown',
            'root_cause_analysis': 'CloudTrail data not available for this resource'
        }
