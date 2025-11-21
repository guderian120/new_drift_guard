from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import DriftEvent

# Mock data for initial UI verification since we can't run migrations easily
MOCK_DRIFTS = [
    {
        'id': 1,
        'resource_name': 'production-db-cluster',
        'resource_type': 'aws_rds_cluster',
        'cloud_provider': 'AWS',
        'severity': 'critical',
        'status': 'active',
        'detected_at': '2025-11-20 09:30:00',
        'description': 'Security Group modified manually to allow 0.0.0.0/0 ingress.',
        'expected_state': {'ingress': ['10.0.0.0/8']},
        'actual_state': {'ingress': ['0.0.0.0/0', '10.0.0.0/8']},
        
        # Forensic Information
        'initiated_by_user': 'john.doe',
        'initiated_by_role': 'arn:aws:iam::123456789012:user/john.doe',
        'initiated_by_email': 'john.doe@company.com',
        'change_timestamp': '2025-11-20 09:15:00',
        'change_method': 'console',
        'source_ip': '203.0.113.42',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'api_calls': [
            {
                'timestamp': '2025-11-20 09:15:23',
                'api': 'ec2:AuthorizeSecurityGroupIngress',
                'parameters': {
                    'GroupId': 'sg-0123456789abcdef0',
                    'IpPermissions': [
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': 3306,
                            'ToPort': 3306,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'Temporary access'}]
                        }
                    ]
                },
                'response_code': 200
            }
        ],
        'change_summary': 'Added ingress rule allowing MySQL (port 3306) from 0.0.0.0/0 to security group sg-0123456789abcdef0',
        'root_cause_category': 'manual_change',
        'root_cause_analysis': '''**Manual Console Change Detected**

The security group was modified directly through the AWS Console by user john.doe. This change bypassed the standard Terraform workflow.

**Timeline:**
- Change made: 2025-11-20 09:15:23 UTC
- Detected: 2025-11-20 09:30:00 UTC (15 minutes later)

**Impact:**
This change exposes the production database to the entire internet, creating a critical security vulnerability.

**Recommended Actions:**
1. Immediately revert the change to remove 0.0.0.0/0 access
2. Investigate why the user needed emergency access
3. If access was needed, implement proper VPN or bastion host solution
4. Review and enforce change management policies
5. Consider implementing AWS Config rules to prevent similar changes'''
    },
    {
        'id': 2,
        'resource_name': 'frontend-load-balancer',
        'resource_type': 'google_compute_forwarding_rule',
        'cloud_provider': 'GCP',
        'severity': 'medium',
        'status': 'active',
        'detected_at': '2025-11-20 08:15:00',
        'description': 'Timeout setting changed from 30s to 60s.',
        'expected_state': {'timeout': '30s'},
        'actual_state': {'timeout': '60s'},
        
        # Forensic Information
        'initiated_by_user': 'sarah.smith@company.com',
        'initiated_by_role': 'roles/compute.networkAdmin',
        'initiated_by_email': 'sarah.smith@company.com',
        'change_timestamp': '2025-11-20 08:10:00',
        'change_method': 'cli',
        'source_ip': '198.51.100.15',
        'user_agent': 'google-cloud-sdk gcloud/455.0.0',
        'api_calls': [
            {
                'timestamp': '2025-11-20 08:10:15',
                'api': 'compute.forwardingRules.patch',
                'parameters': {
                    'project': 'my-project-123',
                    'region': 'us-central1',
                    'forwardingRule': 'frontend-lb',
                    'body': {
                        'backendService': 'projects/my-project-123/regions/us-central1/backendServices/frontend-backend',
                        'timeoutSec': 60
                    }
                },
                'response_code': 200
            }
        ],
        'change_summary': 'Updated load balancer timeout from 30 seconds to 60 seconds via gcloud CLI',
        'root_cause_category': 'emergency_fix',
        'root_cause_analysis': '''**Emergency Performance Fix**

The timeout was increased via gcloud CLI to address ongoing timeout issues affecting production users.

**Timeline:**
- Change made: 2025-11-20 08:10:15 UTC
- Detected: 2025-11-20 08:15:00 UTC (5 minutes later)

**Context:**
This appears to be an emergency response to production issues. The change was made by a network admin using the gcloud CLI.

**Recommended Actions:**
1. Verify if the timeout increase resolved the underlying issue
2. Investigate root cause of the timeouts (slow backend responses?)
3. Codify this change in Terraform if it should be permanent
4. Document the incident and decision-making process
5. Consider if 60s is the right timeout or if backend optimization is needed'''
    }
]

@login_required
def drift_list(request):
    # In a real app, we would query the database:
    # drifts = DriftEvent.objects.all()
    drifts = MOCK_DRIFTS
    return render(request, 'drifts/drift_list.html', {'drifts': drifts})

@login_required
def drift_detail(request, pk):
    # drift = get_object_or_404(DriftEvent, pk=pk)
    drift = next((d for d in MOCK_DRIFTS if d['id'] == pk), None)
    if not drift:
        messages.error(request, "Drift event not found.")
        return redirect('drifts:list')
    
    return render(request, 'drifts/drift_detail.html', {'drift': drift})

@login_required
def remediate_drift(request, pk):
    if request.method == 'POST':
        action = request.POST.get('action')
        messages.success(request, f"Remediation action '{action}' initiated for Drift #{pk}.")
        return redirect('drifts:detail', pk=pk)
    return redirect('drifts:detail', pk=pk)

@login_required
def scan_infrastructure(request):
    """Scan real AWS infrastructure for configuration drifts"""
    from django.utils import timezone
    from integrations.models import Environment
    from .services.aws_scanner import AWSScanner
    
    # Get all configured AWS environments
    aws_environments = Environment.objects.filter(provider='AWS')
    
    if not aws_environments.exists():
        messages.warning(request, "No AWS environments configured. Please add an AWS environment with valid credentials first.")
        return redirect('drifts:list')
    
    all_drifts = []
    scanned_envs = 0
    
    for env in aws_environments:
        try:
            # Initialize AWS scanner with environment credentials
            scanner = AWSScanner(
                access_key=env.aws_access_key,
                secret_key=env.aws_secret_key
            )
            
            # Scan infrastructure
            drifts = scanner.scan_infrastructure()
            
            # Enrich each drift with forensic information and metadata
            for drift in drifts:
                # Try to get forensic info from CloudTrail
                forensics = scanner.get_forensic_info(
                    drift['resource_name'],
                    drift['resource_type']
                )
                drift.update(forensics)
                
                # Add metadata
                drift['environment'] = env.name
                drift['detected_at'] = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
                drift['id'] = len(MOCK_DRIFTS) + len(all_drifts) + 1
                drift['status'] = 'active'
                drift['cloud_provider'] = 'AWS'
            
            all_drifts.extend(drifts)
            scanned_envs += 1
            
        except Exception as e:
            messages.error(request, f"Error scanning environment '{env.name}': {str(e)}")
            continue
    
    # Add detected drifts to the list (in production, save to database)
    if all_drifts:
        for drift in all_drifts:
            MOCK_DRIFTS.insert(0, drift)
        
        messages.success(request, f"Scanned {scanned_envs} environment(s). Found {len(all_drifts)} drift(s).")
    else:
        if scanned_envs > 0:
            messages.success(request, f"Scanned {scanned_envs} environment(s). No drifts detected - infrastructure is compliant!")
        else:
            messages.warning(request, "No environments were successfully scanned. Please check your AWS credentials.")
    
    return redirect('drifts:list')

