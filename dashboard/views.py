from django.shortcuts import render
from django.contrib.auth.decorators import login_required

@login_required
def home(request):
    recent_activity = [
        {'action': 'Drift Detected', 'resource': 'production-db-cluster', 'time': '10 mins ago', 'user': 'System'},
        {'action': 'Remediation Started', 'resource': 'frontend-load-balancer', 'time': '1 hour ago', 'user': 'admin'},
        {'action': 'Drift Detected', 'resource': 'redis-cache-01', 'time': '2 hours ago', 'user': 'System'},
    ]
    context = {
        'total_drifts': 12,
        'critical_drifts': 3,
        'mttr': '45m',
        'recent_activity': recent_activity,
    }
    return render(request, 'dashboard/home.html', context)
