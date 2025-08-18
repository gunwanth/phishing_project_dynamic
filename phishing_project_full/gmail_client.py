from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import os
import pickle
import base64
import json
import streamlit as st


class GmailClient:
    def __init__(self, user_email):
        self.service = None
        self.authenticated = False
        self.SCOPES = ['https://www.googleapis.com/auth/gmail.readonly',
                       'https://www.googleapis.com/auth/gmail.modify']  # added modify for spam marking
        self.user_email = user_email
        self.token_file = f"token_{self.user_email}.pkl"  # Token file per user

    def authenticate(self):
        try:
            creds = None
            # ✅ Try loading token if already authenticated before
            if os.path.exists(self.token_file):
                with open(self.token_file, 'rb') as token:
                    creds = pickle.load(token)

            # ✅ If no creds or invalid, refresh or run OAuth flow
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    # ✅ Check if GOOGLE_CREDENTIALS is set (deployment)
                    creds_json = os.environ.get("GOOGLE_CREDENTIALS")
                    if creds_json:
                        creds_data = json.loads(creds_json)
                        flow = InstalledAppFlow.from_client_config(creds_data, self.SCOPES)
                    else:
                        # ✅ Fallback to local credentials.json (development)
                        flow = InstalledAppFlow.from_client_secrets_file(
                            'credentials.json', self.SCOPES)
                        creds_data = json.loads(st.secrets["GOOGLE_CREDENTIALS"])
                        flow = InstalledAppFlow.from_client_config(creds_data, self.SCOPES)

                    creds = flow.run_local_server(port=0)

                # Save token for future use
                with open(self.token_file, 'wb') as token:
                    pickle.dump(creds, token)

            # Build Gmail API service
            self.service = build('gmail', 'v1', credentials=creds)
            self.authenticated = True
            return True

        except Exception as e:
            print(f"Authentication failed: {str(e)}")
            return False

    def get_recent_emails(self, limit=10):
        if not self.authenticated or self.service is None:
            raise Exception("GmailClient is not authenticated")

        emails = []

        try:
            results = self.service.users().messages().list(userId='me', maxResults=limit).execute()
            messages = results.get('messages', [])

            for msg in messages:
                msg_data = self.service.users().messages().get(
                    userId='me', id=msg['id'], format='full').execute()
                headers = msg_data.get('payload', {}).get('headers', [])
                subject = sender = date = ''

                for header in headers:
                    if header['name'] == 'Subject':
                        subject = header['value']
                    elif header['name'] == 'From':
                        sender = header['value']
                    elif header['name'] == 'Date':
                        date = header['value']

                snippet = msg_data.get('snippet', '')
                body = ''

                parts = msg_data.get('payload', {}).get('parts', [])
                for part in parts:
                    try:
                        if part['mimeType'] == 'text/plain':
                            data = part['body']['data']
                            decoded_bytes = base64.urlsafe_b64decode(data)
                            body = decoded_bytes.decode('utf-8')
                            break
                    except:
                        continue

                emails.append({
                    'id': msg['id'],
                    'thread_id': msg.get('threadId'),
                    'subject': subject,
                    'sender': sender,
                    'date': date,
                    'content': body or snippet,
                    'snippet': snippet,
                    'labels': msg_data.get('labelIds', []),
                    'attachments': []
                })

        except Exception as e:
            print(f"Failed to fetch emails: {e}")

        return emails

    def mark_as_spam(self, msg_id):
        """Mark an email as spam"""
        try:
            self.service.users().messages().modify(
                userId='me',
                id=msg_id,
                body={'addLabelIds': ['SPAM']}
            ).execute()
            return True
        except Exception as e:
            print(f"Failed to mark as spam: {e}")
            return False
