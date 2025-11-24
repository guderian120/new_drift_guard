from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from core.models import AppSettings
from google import genai
import markdown

# Import mock data from drifts app (temporary solution until DB is populated)
from drifts.views import MOCK_DRIFTS

@login_required
@require_POST
def chat_message(request):
    user_message = request.POST.get('message')
    drift_id = int(request.POST.get('drift_id'))
    
    # Get API Key and Model from Settings
    settings = AppSettings.get_solo()
    api_key = settings.gemini_api_key
    selected_model = settings.gemini_model
    
    # Get Drift Context
    drift = next((d for d in MOCK_DRIFTS if d['id'] == drift_id), None)
    
    # Check if API key is properly configured (not None and not empty string)
    if not api_key or not api_key.strip():
        ai_response = """⚠️ **AI Assistant Not Configured**
        
Please configure your Google Gemini API key in [Settings](/settings/) to use the AI assistant.

**Quick Setup:**
1. Get a free API key from [Google AI Studio](https://aistudio.google.com/app/apikey)
2. Go to [Settings](/settings/) and paste your API key
3. Save and return here to chat!"""
    elif not drift:
        ai_response = "⚠️ **Error:** Unable to load drift event context. Please refresh the page."
    else:
        try:
            # Create client with API key
            client = genai.Client(api_key=api_key)
            
            context_prompt = f"""
            You are an expert Infrastructure Engineer assistant named DriftGuard AI.
            Analyze the following infrastructure drift event and answer the user's question.
            
            Drift Context:
            - Resource: {drift['resource_name']} ({drift['resource_type']})
            - Provider: {drift['cloud_provider']}
            - Severity: {drift['severity']}
            - Description: {drift['description']}
            - Expected State: {drift['expected_state']}
            - Actual State: {drift['actual_state']}
            
            Change Initiator (Forensic Information):
            - Initiated By: {drift.get('initiated_by_user', 'Unknown')}
            - Email: {drift.get('initiated_by_email', 'Unknown')}
            - Role/ARN: {drift.get('initiated_by_role', 'Unknown')}
            - Change Timestamp: {drift.get('change_timestamp', 'Unknown')}
            - Change Method: {drift.get('change_method', 'Unknown')} (console/CLI/API)
            - Source IP: {drift.get('source_ip', 'Unknown')}
            - Change Summary: {drift.get('change_summary', 'Not available')}
            - Root Cause Category: {drift.get('root_cause_category', 'Unknown')}
            
            User Question: {user_message}
            
            Provide a concise, technical, and helpful response. If the user asks about who made the change or why,
            reference the forensic information above. Be specific about the change initiator and timeline.
            """
            
            response = client.models.generate_content(
                model=selected_model,
                contents=context_prompt
            )
            ai_response = markdown.markdown(response.text)
            
        except Exception as e:
            error_str = str(e).lower()
            
            # Provide user-friendly error messages based on error type
            if '401' in error_str or 'unauthorized' in error_str or 'invalid' in error_str:
                ai_response = """⚠️ **Invalid API Key**
                
Your Gemini API key appears to be invalid or expired.

**How to fix:**
1. Go to [Google AI Studio](https://aistudio.google.com/app/apikey)
2. Generate a new API key
3. Update it in [Settings](/settings/)"""
                
            elif '404' in error_str or 'not found' in error_str:
                ai_response = f"""⚠️ **Model Not Available**
                
The selected AI model is not available with your API key.

**How to fix:**
1. Go to [Settings](/settings/)
2. Try selecting a different AI model (e.g., "Gemini 2.5 Flash")
3. Save and try again

If the issue persists, your API key may need additional permissions."""
                
            elif '429' in error_str or 'quota' in error_str or 'rate limit' in error_str:
                ai_response = """⚠️ **Rate Limit Exceeded**
                
You've reached the API usage limit for your key.

**What to do:**
- Wait a few minutes and try again
- Check your quota at [Google AI Studio](https://aistudio.google.com/app/apikey)
- Consider upgrading your API plan if needed"""
                
            elif 'network' in error_str or 'connection' in error_str or 'timeout' in error_str:
                ai_response = """⚠️ **Connection Error**
                
Unable to connect to the Gemini API.

**Troubleshooting:**
- Check your internet connection
- Try again in a moment
- If the issue persists, the API may be temporarily unavailable"""
                
            else:
                # Generic error message for unknown issues
                ai_response = """⚠️ **AI Assistant Error**
                
The AI assistant encountered an unexpected error.

**What to try:**
1. Refresh the page and try again
2. Check your API key in [Settings](/settings/)
3. Try selecting a different AI model

If the problem continues, please contact support."""
    
    context = {
        'user_message': user_message,
        'ai_response': ai_response,
    }
    return render(request, 'chat/message_fragment.html', context)
