from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import DriftEvent
import logging

logger = logging.getLogger(__name__)

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
    """Initiate infrastructure scan with progress tracking"""
    from .scan_progress import create_scan_session
    import threading
    
    # Create a new scan session
    session_id = create_scan_session()
    
    # Start scan in background thread
    thread = threading.Thread(target=_perform_scan, args=(session_id,))
    thread.daemon = True
    thread.start()
    
    # Redirect to progress page
    return render(request, 'drifts/scan_progress.html', {'session_id': session_id})


def _perform_scan(session_id: str):
    """Perform the actual scan with progress tracking"""
    from django.utils import timezone
    from integrations.models import Environment
    from .services.aws_scanner import AWSScanner
    from .services.terraform_parser import TerraformParser
    from .scan_progress import get_scan_session
    
    progress = get_scan_session(session_id)
    if not progress:
        return
    
    # Initialize steps
    init_step = progress.add_step("Initializing Scan", "Preparing to scan cloud infrastructure")
    progress.start_step(init_step)
    
    try:
        # Get all configured AWS environments
        aws_environments = Environment.objects.filter(provider='AWS')
        
        if not aws_environments.exists():
            progress.error_step(init_step, "No AWS environments configured")
            progress.complete_scan(0, 0)
            return
        
        progress.add_log(init_step, f"Found {aws_environments.count()} AWS environment(s)", 'success')
        progress.complete_step(init_step, {'Environments': aws_environments.count()})
        
        all_drifts = []
        scanned_envs = 0
        
        for env in aws_environments:
            env_step = progress.add_step(f"Scanning {env.name}", f"Processing environment: {env.name}")
            progress.start_step(env_step)
            
            try:
                # Initialize AWS scanner
                progress.add_log(env_step, "Initializing AWS scanner...", 'info')
                scanner = AWSScanner(
                    access_key=env.aws_access_key,
                    secret_key=env.aws_secret_key
                )
                progress.update_step_progress(env_step, 20)
                
                expected_state = None
                
                # If IaC repository is configured, parse it
                if env.iac_repo_url:
                    repo_step = progress.add_step("Cloning IaC Repository", f"Fetching Terraform files from {env.iac_repo_url}")
                    progress.start_step(repo_step)
                    
                    try:
                        progress.add_log(repo_step, f"Cloning repository: {env.iac_repo_url}", 'info')
                        parser = TerraformParser(
                            repo_url=env.iac_repo_url,
                            repo_token=getattr(env, 'iac_repo_token', None)
                        )
                        progress.update_step_progress(repo_step, 30)
                        
                        progress.add_log(repo_step, "Repository cloned successfully", 'success')
                        progress.update_step_progress(repo_step, 50)
                        
                        parse_step = progress.add_step("Parsing Terraform Files", "Extracting resource definitions")
                        progress.start_step(parse_step)
                        
                        expected_state = parser.parse_repository()
                        total_resources = sum(len(v) for v in expected_state.values())
                        
                        progress.add_log(parse_step, f"Found {total_resources} resource(s) in Terraform", 'success')
                        progress.complete_step(parse_step, {'Resources Found': total_resources})
                        progress.complete_step(repo_step, {'Status': 'Success'})
                        
                    except Exception as e:
                        logger.error(f"Failed to parse Terraform repository: {str(e)}")
                        progress.error_step(repo_step, f"Failed to parse repository: {str(e)}")
                        progress.add_log(env_step, "Falling back to policy violation checks", 'warning')
                else:
                    progress.add_log(env_step, "No IaC repository configured - using policy checks", 'info')
                
                progress.update_step_progress(env_step, 50)
                
                # Scan infrastructure
                scan_step = progress.add_step("Scanning AWS Resources", "Comparing actual vs expected state")
                progress.start_step(scan_step)
                
                progress.add_log(scan_step, "Scanning EC2 instances...", 'info')
                progress.update_step_progress(scan_step, 25)
                
                progress.add_log(scan_step, "Scanning S3 buckets...", 'info')
                progress.update_step_progress(scan_step, 50)
                
                progress.add_log(scan_step, "Scanning Security Groups...", 'info')
                progress.update_step_progress(scan_step, 75)
                
                drifts = scanner.scan_infrastructure(expected_state=expected_state)
                
                progress.add_log(scan_step, f"Found {len(drifts)} drift(s)", 'success' if len(drifts) == 0 else 'warning')
                progress.complete_step(scan_step, {'Drifts Found': len(drifts)})
                
                # Enrich drifts with forensic information and metadata
                if drifts:
                    forensic_step = progress.add_step("Gathering Forensic Data", "Collecting change history from CloudTrail")
                    progress.start_step(forensic_step)
                    
                    forensics_collected = 0
                    for drift in drifts:
                        # Try to get forensic info from CloudTrail
                        try:
                            progress.add_log(forensic_step, f"Checking CloudTrail for {drift['resource_name']}...", 'info')
                            forensics = scanner.get_forensic_info(
                                drift['resource_name'],
                                drift['resource_type']
                            )
                            drift.update(forensics)
                            forensics_collected += 1
                        except Exception as e:
                            logger.warning(f"Could not get forensics for {drift['resource_name']}: {str(e)}")
                            # Add default forensic info
                            drift.update({
                                'initiated_by_user': 'Unknown',
                                'change_timestamp': timezone.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'change_method': 'unknown',
                                'change_summary': 'Drift detected during infrastructure scan',
                                'root_cause_category': 'unknown',
                                'root_cause_analysis': 'CloudTrail data not available for this resource'
                            })
                        
                        # Add metadata
                        drift['environment'] = env.name
                        drift['detected_at'] = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
                        drift['id'] = len(MOCK_DRIFTS) + len(all_drifts) + 1
                        drift['status'] = 'active'
                        drift['cloud_provider'] = 'AWS'
                    
                    progress.add_log(forensic_step, f"Collected forensic data for {forensics_collected}/{len(drifts)} drift(s)", 'success')
                    progress.complete_step(forensic_step, {'Forensics Collected': forensics_collected})
                else:
                    # No drifts, just add metadata
                    for drift in drifts:
                        drift['environment'] = env.name
                        drift['detected_at'] = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
                        drift['id'] = len(MOCK_DRIFTS) + len(all_drifts) + 1
                        drift['status'] = 'active'
                        drift['cloud_provider'] = 'AWS'
                
                all_drifts.extend(drifts)
                scanned_envs += 1
                
                progress.complete_step(env_step, {
                    'Drifts': len(drifts),
                    'Status': 'Complete'
                })
                
            except Exception as e:
                logger.exception(f"Error scanning environment '{env.name}'")
                progress.error_step(env_step, f"Error: {str(e)}")
                continue
        
        # Add drifts to mock list
        for drift in all_drifts:
            MOCK_DRIFTS.insert(0, drift)
        
        # Mark scan as complete
        progress.complete_scan(len(all_drifts), scanned_envs)
        
    except Exception as e:
        logger.exception("Fatal error during scan")
        if init_step < len(progress.steps):
            progress.error_step(init_step, f"Fatal error: {str(e)}")
        progress.complete_scan(0, 0)


@login_required
def scan_progress_view(request, session_id):
    """Return scan progress for HTMX polling"""
    from .scan_progress import get_scan_session
    
    progress = get_scan_session(session_id)
    if not progress:
        return render(request, 'drifts/scan_progress_steps.html', {
            'steps': [],
            'scan_complete': True,
            'total_drifts': 0,
            'scanned_envs': 0
        })
    
    return render(request, 'drifts/scan_progress_steps.html', progress.to_dict())
