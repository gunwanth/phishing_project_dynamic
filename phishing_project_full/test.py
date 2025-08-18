from gmail_client import GmailClient

client = GmailClient()

if client.authenticate():
    emails = client.get_recent_emails(5)
    for e in emails:
        print(f"Subject: {e['subject']}")
        print(f"Sender: {e['sender']}")
        print(f"Snippet: {e['snippet']}")
        print("-" * 40)
else:
    print("Failed to authenticate Gmail client.")
