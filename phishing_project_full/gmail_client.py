import os
import pickle
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import base64

# Gmail API scopes
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify'
]

class GmailClient:
    def __init__(self, user_email):
        self.user_email = user_email
        self.token_path = f"token_{user_email}.pkl"
        self.creds = None
        self.service = None

    def authenticate(self):
        """Authenticate user and create Gmail service"""
        try:
            # Load existing token
            if os.path.exists(self.token_path):
                with open(self.token_path, 'rb') as token_file:
                    self.creds = pickle.load(token_file)

            # OAuth flow if no valid token
            if not self.creds or not self.creds.valid:
                print("Starting OAuth flow...")
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                self.creds = flow.run_local_server(port=0)
                with open(self.token_path, 'wb') as token_file:
                    pickle.dump(self.creds, token_file)

            # Build Gmail service
            self.service = build('gmail', 'v1', credentials=self.creds)

            if self.service:
                print("✅ Gmail service created successfully.")
                return True
            else:
                print("❌ Gmail service not created.")
                return False

        except Exception as e:
            print(f"Authentication error: {e}")
            return False

    def get_recent_emails(self, limit=20):
        """Fetch recent emails"""
        if not self.service:
            raise ValueError("Gmail service not initialized. Call authenticate() first.")

        results = self.service.users().messages().list(userId='me', maxResults=limit).execute()
        messages = results.get('messages', [])
        emails = []

        for msg in messages:
            m = self.service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            payload = m['payload']
            headers = {h['name']: h['value'] for h in payload.get('headers', [])}
            content = ""

            # Extract plain text content
            if 'parts' in payload:
                for part in payload['parts']:
                    if part['mimeType'] == 'text/plain':
                        data = part['body'].get('data')
                        if data:
                            content += base64.urlsafe_b64decode(data).decode('utf-8')

            emails.append({
                'id': m['id'],
                'sender': headers.get('From', ''),
                'subject': headers.get('Subject', ''),
                'date': headers.get('Date', ''),
                'content': content,
                'labels': m.get('labelIds', [])
            })

        return emails

    def mark_as_spam(self, email_id):
        """Move email to SPAM"""
        if not self.service:
            return False
        try:
            self.service.users().messages().modify(
                userId='me',
                id=email_id,
                body={'addLabelIds': ['SPAM']}
            ).execute()
            return True
        except Exception as e:
            print(f"Error marking spam: {e}")
            return False
