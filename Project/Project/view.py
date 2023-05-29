from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import redirect, render
from django.views import View
import google_auth_oauthlib

from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2 import credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

# Create your views here.

SCOPES = ['https://www.googleapis.com/auth/calendar']


def index(request):
    return redirect('GoogleCalendarInitView')


class GoogleCalendarInitView(View):
    def get(self, request):
        # Create a flow instance with the OAuth2 configuration
        flow = Flow.from_client_config({
                    "web": {
                        "client_id": settings.CLIENT_ID,
                        "client_secret": settings.CLIENT_SECRET,
                        "redirect_uris": [],
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://accounts.google.com/o/oauth2/token"
                    }
                },
                scopes=SCOPES
            )

        flow.redirect_uri = 'http://127.0.0.1:8000/rest/v1/calendar/redirect'

        # Generate the authorization URL
        authorization_url, state = flow.authorization_url(access_type='offline')

        # Save the state in session (for CSRF protection)
        request.session['state'] = state

        # Redirect the user to the authorization URL
        return HttpResponseRedirect(authorization_url)



class GoogleCalendarRedirectView(View):
    def get(self, request):
        # Check if the state in the session matches the state received from the redirect
        if 'state' not in request.session or request.GET.get('state') != request.session['state']:
            return HttpResponse('Invalid state parameter', status=400)

        # Create a flow instance with the OAuth2 configuration
        flow = Flow.from_client_config({
                    "web": {
                        "client_id": settings.CLIENT_ID,
                        "client_secret": settings.CLIENT_SECRET,
                        "redirect_uris": [],
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://accounts.google.com/o/oauth2/token"
                    }
                },
                scopes=SCOPES
            )
        flow.redirect_uri = 'http://127.0.0.1:8000/rest/v1/calendar/redirect'
        import os 
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
        print(request.build_absolute_uri())
        # Exchange the authorization code for credentials
        authorization_response = request.build_absolute_uri()
        try:
            flow.fetch_token(authorization_response=authorization_response)
        except Exception as e:
            print(e)
            return redirect('GoogleCalendarInitView')
        # Get the access token and save it in the database
        credentials = flow.credentials
        access_token = credentials.token
        # Save the access token (you may associate it with a user in your system)

        # Use the access token to fetch the list of events
        service = build('calendar', 'v3', credentials=credentials)
        events_result = service.events().list(calendarId='primary', maxResults=10).execute()
        events = events_result.get('items', [])
        

        return JsonResponse(events, safe=False)
    