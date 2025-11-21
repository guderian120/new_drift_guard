import os
import subprocess
import tempfile
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class RepositoryCloner:
    """Clone and manage IaC repositories"""
    
    def __init__(self, repo_url: str, username: Optional[str] = None, token: Optional[str] = None):
        """
        Initialize repository cloner
        
        Args:
            repo_url: Git repository URL
            username: Username for private repo authentication
            token: Personal access token for private repo authentication
        """
        self.repo_url = repo_url
        self.username = username
        self.token = token
        
    def clone_repository(self, target_dir: Optional[str] = None) -> str:
        """
        Clone repository to target directory
        
        Args:
            target_dir: Directory to clone into (creates temp dir if None)
            
        Returns:
            Path to cloned repository
        """
        if target_dir is None:
            target_dir = tempfile.mkdtemp(prefix='iac_repo_')
        
        try:
            if self.username and self.token:
                # Authenticated clone for private repos
                # Format: https://username:token@github.com/user/repo.git
                auth_url = self.repo_url.replace('https://', f'https://{self.username}:{self.token}@')
                subprocess.run(
                    ['git', 'clone', '--depth', '1', auth_url, target_dir],
                    check=True,
                    capture_output=True,
                    text=True
                )
            else:
                # Public repo clone
                subprocess.run(
                    ['git', 'clone', '--depth', '1', self.repo_url, target_dir],
                    check=True,
                    capture_output=True,
                    text=True
                )
            
            logger.info(f"Successfully cloned repository to {target_dir}")
            return target_dir
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error cloning repository: {e.stderr}")
            raise Exception(f"Failed to clone repository: {e.stderr}")
    
    def pull_latest(self, repo_dir: str):
        """
        Pull latest changes from repository
        
        Args:
            repo_dir: Path to existing repository
        """
        try:
            subprocess.run(
                ['git', '-C', repo_dir, 'pull'],
                check=True,
                capture_output=True,
                text=True
            )
            logger.info(f"Successfully pulled latest changes in {repo_dir}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error pulling repository: {e.stderr}")
            raise Exception(f"Failed to pull repository: {e.stderr}")
    
    @staticmethod
    def is_git_installed() -> bool:
        """Check if git is installed on the system"""
        try:
            subprocess.run(['git', '--version'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
