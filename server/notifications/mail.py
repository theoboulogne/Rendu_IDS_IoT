from __future__ import print_function

import os.path

import base64
from email.mime.text import MIMEText


from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json. The scope is used to give access on what we can do with the gmail API (edit, read, etc).
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
SENDER = ''




def get_creds() -> Credentials:
    """
    Gets the credentials from the user's machine.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.

    if os.path.exists('server/notifications/creds/token.json'):
        creds = Credentials.from_authorized_user_file('server/notifications/creds/token.json', SCOPES)

    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())

        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'server/notifications/creds/credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials for the next run
        with open('server/notifications/creds/token.json', 'w') as token:
            token.write(creds.to_json())

    return creds




def send_email(recipient: str, subject: str, body: str):
    """
    Sends an email to the specified recipient using the Gmail API.

    Args:
        recipient (string): email that will receive the notification.
        subject (string): subject of the notification.
        body (string): body the notification.
    """
    creds = get_creds()

    try:
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)
        
        # Set the default sender of the email

        # Create a message object and encode it as a base64 string
        message = MIMEText(body)
        message['to'] = recipient
        message['subject'] = subject
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()

        # Send the email using the Gmail API
        send_message = service.users().messages().send(userId=SENDER, body={'raw': raw}).execute()
        print(F'sent message to : {recipient} ; Message Id: {send_message["id"]}')

    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f'An error occurred: {error}')






if __name__ == "__main__":
    recipient_email = 'comando117000@gmail.com'
    subject = 'Test email'
    body = 'This is a test email.'

    send_email(recipient_email, subject, body)
