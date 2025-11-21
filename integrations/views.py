from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Environment
from .forms import EnvironmentForm

@login_required
def environment_list(request):
    environments = Environment.objects.all().order_by('-created_at')
    return render(request, 'integrations/environment_list.html', {'environments': environments})

@login_required
def environment_create(request):
    if request.method == 'POST':
        form = EnvironmentForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Environment created successfully with validated credentials.")
            return redirect('integrations:list')
        else:
            messages.error(request, "Failed to create environment. Please check the errors below.")
    else:
        form = EnvironmentForm()
    
    return render(request, 'integrations/environment_form.html', {'form': form, 'action': 'Create'})

@login_required
def environment_update(request, pk):
    environment = get_object_or_404(Environment, pk=pk)
    
    if request.method == 'POST':
        form = EnvironmentForm(request.POST, instance=environment)
        if form.is_valid():
            form.save()
            messages.success(request, f"Environment '{environment.name}' updated successfully.")
            return redirect('integrations:list')
        else:
            messages.error(request, "Failed to update environment. Please check the errors below.")
    else:
        form = EnvironmentForm(instance=environment)
    
    return render(request, 'integrations/environment_form.html', {
        'form': form,
        'action': 'Update',
        'environment': environment
    })

@login_required
def environment_delete(request, pk):
    environment = get_object_or_404(Environment, pk=pk)
    
    if request.method == 'POST':
        env_name = environment.name
        environment.delete()
        messages.success(request, f"Environment '{env_name}' deleted successfully.")
        return redirect('integrations:list')
    
    return render(request, 'integrations/environment_confirm_delete.html', {'environment': environment})
