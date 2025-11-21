from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import AppSettings
from .forms import AppSettingsForm

@login_required
def settings_view(request):
    app_settings = AppSettings.get_solo()
    
    if request.method == 'POST':
        form = AppSettingsForm(request.POST, instance=app_settings)
        if form.is_valid():
            form.save()
            messages.success(request, 'Settings updated successfully.')
            return redirect('core:settings')
    else:
        form = AppSettingsForm(instance=app_settings)
    
    return render(request, 'core/settings.html', {'form': form})

from integrations.models import Environment
from integrations.services.repo_cloner import RepositoryCloner
from integrations.services.iac_parser import IaCParser
from integrations.services.architecture_generator import ArchitectureGenerator
import shutil
import logging
import os

logger = logging.getLogger(__name__)

@login_required
def architecture_view(request):
    """Generate architecture diagrams from IaC repositories"""
    environments = Environment.objects.all()
    diagrams = {}
    errors = []
    
    # Check if Git is installed
    if not RepositoryCloner.is_git_installed():
        messages.error(request, "Git is not installed on the system. Please install Git to view architecture diagrams.")
        return render(request, 'core/architecture.html', {
            'diagrams': {},
            'environments': environments,
            'has_environments': environments.exists()
        })
    
    for env in environments:
        if not env.iac_repo_url:
            logger.info(f"Environment {env.name} has no IaC repository configured")
            continue
        
        temp_dir = None
        try:
            # Clone repository
            logger.info(f"Cloning repository for environment: {env.name}")
            cloner = RepositoryCloner(
                env.iac_repo_url,
                getattr(env, 'iac_repo_username', None),
                getattr(env, 'iac_repo_token', None)
            )
            temp_dir = cloner.clone_repository()
            
            # Read IaC files content for AI analysis
            iac_content = _read_iac_files(temp_dir)
            
            # Parse IaC files (for fallback and resource counting)
            logger.info(f"Parsing IaC files for environment: {env.name}")
            iac_tool = getattr(env, 'iac_tool_detected', None) or 'terraform'
            parser = IaCParser(temp_dir, iac_tool)
            infrastructure = parser.parse_infrastructure()
            
            # Get Gemini API key
            from core.models import AppSettings
            app_settings = AppSettings.get_solo()
            gemini_api_key = app_settings.gemini_api_key if app_settings else None
            
            # Generate diagram with AI
            logger.info(f"Generating AI-powered diagram for environment: {env.name}")
            generator = ArchitectureGenerator(gemini_api_key=gemini_api_key)
            diagram = generator.generate_diagram(
                infrastructure, 
                env.provider,
                iac_files_content=iac_content
            )
            
            diagrams[env.id] = {
                'name': env.name,
                'provider': env.provider,
                'diagram': diagram,
                'resource_count': {
                    'vpcs': len(infrastructure.get('vpcs', [])),
                    'ec2_instances': len(infrastructure.get('ec2_instances', [])),
                    'rds_instances': len(infrastructure.get('rds_instances', [])),
                    'load_balancers': len(infrastructure.get('load_balancers', [])),
                }
            }
            
            logger.info(f"Successfully generated diagram for {env.name}")
            
        except Exception as e:
            error_msg = f"Error generating diagram for {env.name}: {str(e)}"
            logger.error(error_msg)
            errors.append(error_msg)
            
            # Add placeholder diagram for failed environments
            diagrams[env.id] = {
                'name': env.name,
                'provider': env.provider,
                'diagram': f"graph TB\n    Error[\"Error: {str(e)}\"]",
                'resource_count': {}
            }
        
        finally:
            # Cleanup temp directory (with Windows file locking handling)
            if temp_dir:
                try:
                    import stat
                    import time
                    
                    def handle_remove_readonly(func, path, exc):
                        """Handle read-only files on Windows"""
                        if os.path.exists(path):
                            os.chmod(path, stat.S_IWRITE)
                            func(path)
                    
                    shutil.rmtree(temp_dir, onerror=handle_remove_readonly)
                except Exception as e:
                    # Silently ignore cleanup errors - they don't affect functionality
                    logger.debug(f"Temp directory cleanup deferred: {e}")
    
    # Show errors to user
    for error in errors:
        messages.warning(request, error)
    
    return render(request, 'core/architecture.html', {
        'diagrams': diagrams,
        'environments': environments,
        'has_environments': environments.exists()
    })

def _read_iac_files(repo_path: str, max_size: int = 50000) -> str:
    """
    Read IaC files from repository for AI analysis
    
    Args:
        repo_path: Path to cloned repository
        max_size: Maximum total characters to read
        
    Returns:
        Combined content of IaC files
    """
    content_parts = []
    total_size = 0
    
    # File extensions to read
    iac_extensions = ['.tf', '.yaml', '.yml', '.json']
    
    for root, dirs, files in os.walk(repo_path):
        # Skip .git and .terraform directories
        if '.git' in root or '.terraform' in root:
            continue
            
        for file in files:
            if any(file.endswith(ext) for ext in iac_extensions):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        file_content = f.read()
                        
                    # Add file header
                    content_parts.append(f"\n### File: {file}\n{file_content}\n")
                    total_size += len(file_content)
                    
                    # Stop if we've read enough
                    if total_size >= max_size:
                        break
                        
                except Exception as e:
                    logger.warning(f"Could not read {file_path}: {e}")
                    continue
        
        if total_size >= max_size:
            break
    
    return ''.join(content_parts)
