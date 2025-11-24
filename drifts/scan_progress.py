"""
Scan progress tracking system
Stores scan progress in memory for real-time updates
"""
from datetime import datetime
from typing import Dict, List, Any
import uuid

# In-memory storage for scan progress
# In production, use Redis or database
SCAN_SESSIONS = {}


class ScanProgress:
    """Track progress of infrastructure scan"""
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.steps = []
        self.current_step = None
        self.start_time = datetime.now()
        self.end_time = None
        self.total_drifts = 0
        self.scanned_envs = 0
        
    def add_step(self, title: str, description: str = ""):
        """Add a new step to the progress"""
        step = {
            'id': len(self.steps),
            'title': title,
            'description': description,
            'status': 'pending',  # pending, in_progress, completed, error
            'start_time': None,
            'end_time': None,
            'duration': '',
            'progress': 0,
            'logs': [],
            'results': {}
        }
        self.steps.append(step)
        return step['id']
    
    def start_step(self, step_id: int):
        """Mark a step as in progress"""
        if step_id < len(self.steps):
            self.steps[step_id]['status'] = 'in_progress'
            self.steps[step_id]['start_time'] = datetime.now()
            self.current_step = step_id
    
    def update_step_progress(self, step_id: int, progress: int):
        """Update step progress percentage"""
        if step_id < len(self.steps):
            self.steps[step_id]['progress'] = min(100, max(0, progress))
    
    def add_log(self, step_id: int, message: str, level: str = 'info'):
        """Add a log message to a step"""
        if step_id < len(self.steps):
            self.steps[step_id]['logs'].append({
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'message': message,
                'level': level  # info, success, warning, error
            })
    
    def complete_step(self, step_id: int, results: Dict[str, Any] = None):
        """Mark a step as completed"""
        if step_id < len(self.steps):
            self.steps[step_id]['status'] = 'completed'
            self.steps[step_id]['end_time'] = datetime.now()
            
            # Calculate duration
            if self.steps[step_id]['start_time']:
                duration = (self.steps[step_id]['end_time'] - 
                           self.steps[step_id]['start_time']).total_seconds()
                self.steps[step_id]['duration'] = f"{duration:.1f}s"
            
            if results:
                self.steps[step_id]['results'] = results
    
    def error_step(self, step_id: int, error_message: str):
        """Mark a step as errored"""
        if step_id < len(self.steps):
            self.steps[step_id]['status'] = 'error'
            self.steps[step_id]['end_time'] = datetime.now()
            self.add_log(step_id, error_message, 'error')
    
    def complete_scan(self, total_drifts: int, scanned_envs: int):
        """Mark the entire scan as complete"""
        self.end_time = datetime.now()
        self.total_drifts = total_drifts
        self.scanned_envs = scanned_envs
    
    def is_complete(self):
        """Check if scan is complete"""
        return self.end_time is not None
    
    def to_dict(self):
        """Convert to dictionary for template rendering"""
        return {
            'session_id': self.session_id,
            'steps': self.steps,
            'scan_complete': self.is_complete(),
            'total_drifts': self.total_drifts,
            'scanned_envs': self.scanned_envs
        }


def create_scan_session() -> str:
    """Create a new scan session"""
    session_id = str(uuid.uuid4())
    SCAN_SESSIONS[session_id] = ScanProgress(session_id)
    return session_id


def get_scan_session(session_id: str) -> ScanProgress:
    """Get a scan session by ID"""
    return SCAN_SESSIONS.get(session_id)


def cleanup_old_sessions():
    """Remove sessions older than 1 hour"""
    from datetime import timedelta
    cutoff = datetime.now() - timedelta(hours=1)
    
    to_remove = []
    for session_id, progress in SCAN_SESSIONS.items():
        if progress.start_time < cutoff:
            to_remove.append(session_id)
    
    for session_id in to_remove:
        del SCAN_SESSIONS[session_id]
