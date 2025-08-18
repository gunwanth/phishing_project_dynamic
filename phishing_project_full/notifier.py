import requests
import os

# Example: Pushover (you can use any other service like Telegram, IFTTT, etc.)
PUSHOVER_TOKEN = os.getenv("aakr7dnjii66qcage12f91y935nu2h")  # App token from Pushover
PUSHOVER_USER_KEY = os.getenv("upgveqyysb3em83dgd98d2jrw3wbqh")  # Your Pushover user key

def send_notification(title, message):
    if not PUSHOVER_TOKEN or not PUSHOVER_USER_KEY:
        print("Pushover credentials missing.")
        return False

    response = requests.post(
        "https://api.pushover.net/1/messages.json",
        data={
            "token": PUSHOVER_TOKEN,
            "user": PUSHOVER_USER_KEY,
            "title": title,
            "message": message
        }
    )
    return response.status_code == 200