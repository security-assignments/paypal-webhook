# https://github.com/paypal/PayPal-Python-SDK/blob/master/samples/notification/webhook-events/verify_webhook_events.py
from flask import jsonify
from googleapiclient.discovery import build
from google.auth import default, iam
from google.auth.transport import requests as gauthtransportrequests
from google.oauth2 import service_account

from googleapiclient.errors import HttpError
from email.message import EmailMessage
import base64
import os
import hashlib
import requests
import yaml

from dotenv import load_dotenv

load_dotenv()

env_file = "env.yml"
if os.environ.get("LOCAL_DEV"):
    if os.path.exists(env_file):
        with open(env_file) as f:
            env_vars = yaml.safe_load(f)
        for key, value in env_vars.items():
            os.environ[key] = str(value)


def do_webhook(request):

    if not "PAYPAL_MOCK" in os.environ:
        paypal_verified = paypal_verify(request)
        if not paypal_verified:
            print(request.headers)

            print(".data.decode('utf-8')")
            print(request.data.decode('utf-8'))
            print()

            raise Exception('Paypal transaction did not verify! See logs.')


    # https://developer.paypal.com/docs/api-basics/notifications/webhooks/notification-messages/
    # https://developer.paypal.com/docs/api/orders/v1/#orders_get
    payload = request.get_json()
    amount = payload['resource']['amount']['value']
    custom_sig = payload['resource']['custom_id']
    
    to_emails = []

    gcp_email = payload['resource']['invoice_id']
    to_emails.append( gcp_email )

    buyer_email = (
        payload.get("resource", {})
            .get("payee", {})
            .get("email_address")
        or payload.get("resource", {})
            .get("payer", {})
            .get("email_address")
        or payload.get("resource", {})
            .get("payer", {})
            .get("payer_info", {})
            .get("email")
        or payload.get("resource", {})
            .get("subscriber", {})
            .get("email_address")
    )

    if buyer_email:
        to_emails.append(buyer_email)

    # support_email = os.environ['SUPPORT_EMAIL']

    extra_message = ''

    if not "PAYPAL_MOCK" in os.environ:
        if 'sandbox' in request.headers.get('Paypal-Cert-Url'):
            mode = 'sandbox'
        else:
            mode = 'live'
    else:
        mode = 'sandbox'

    if "SKIP_CUSTOM_SIG_VERIFIED" in os.environ:
        custom_sig_verified = True
    else:
        custom_sig_verified = custom_sig_verify(gcp_email, amount, custom_sig)
    if not custom_sig_verified:

        # to_emails.append(support_email)
        extra_message =  (
            f'<br/> Error reason: bad signature.'
            # f'<br/> This error has been reported to <strong>{support_email}</strong>. You should receive help soon.'
        )
        result_adverb='unsuccessfully'

        send_an_email(to_emails, mode, result_adverb, gcp_email, extra_message)

        return '', 200

    try:
        add_to_google_group(gcp_email, mode)
        result_adverb = "successfully"
        extra_message = (
            '<br/> Your gcp email should now have access to the security-assignments.com lab virtual machines.'
        )
        to_emails.append('access-granted@security-assignments.com')
    except HttpError as e:
        extra_message = (
            f'<br/> Error response status code : {e.status_code}, reason : {e.error_details}'
            # '<br/>'
            # f'<br/> This error has been reported to <strong>{support_email}</strong>. You should receive help soon.'
        )
        result_adverb = "unsuccessfully"
        # to_emails.append(support_email)

    send_an_email(to_emails, mode, result_adverb, gcp_email, extra_message)

    return '', 200


def send_an_email(to_emails, mode, result_adverb, gcp_email, extra_message = ''):

    subject = f"User {result_adverb} added to google group"

    if mode == 'live':
        google_group = os.environ['GOOGLE_GROUP_NAME']
    else:
        google_group = os.environ['SANDBOX_GOOGLE_GROUP_NAME']
        subject += ' (sandbox)'


    content = f'Hello, your gcp email <strong>{gcp_email}</strong> was {result_adverb} addded to the <strong>{google_group}</strong> google group.'
    if extra_message:
        content += f'<br/>{extra_message}'
    # print(content)

    send_email(to_emails, subject, content)



def paypal_verify(request):
    # The payload body sent in the webhook event
    event_body = request.data.decode('utf-8')

    verified = verify_webhook(request.headers, event_body)

    return verified


def verify_webhook(headers, body):
    """
    headers: dict from incoming request
    body: raw request data (str), not parsed JSON
    """

    if "sandbox" in headers["Paypal-Cert-Url"]:
        PAYPAL_BASE = "https://api-m.sandbox.paypal.com"
        PAYPAL_CLIENT_ID = os.environ["PAYPAL_SANDBOX_CLIENT_ID"]
        PAYPAL_CLIENT_SECRET = os.environ["PAYPAL_SANDBOX_CLIENT_SECRET"]
        PAYPAL_WEBHOOK_ID = os.environ['PAYPAL_WEBHOOK_ID_SANDBOX']
    else:
        PAYPAL_BASE = "https://api-m.paypal.com"
        PAYPAL_CLIENT_ID = os.environ["PAYPAL_LIVE_CLIENT_ID"]
        PAYPAL_CLIENT_SECRET = os.environ["PAYPAL_LIVE_CLIENT_SECRET"]
        PAYPAL_WEBHOOK_ID = os.environ['PAYPAL_WEBHOOK_ID_LIVE']

    transmission_id = headers["Paypal-Transmission-Id"]
    transmission_time = headers["Paypal-Transmission-Time"]
    transmission_sig = headers["Paypal-Transmission-Sig"]
    cert_url = headers["Paypal-Cert-Url"]
    auth_algo = headers["Paypal-Auth-Algo"]

    # Prepare verification payload
    payload = f'''{{ 
        "auth_algo": "{ auth_algo }", 
        "cert_url": "{ cert_url }", 
        "transmission_id": "{ transmission_id }", 
        "transmission_sig": "{ transmission_sig }", 
        "transmission_time": "{ transmission_time }", 
        "webhook_id": "{ PAYPAL_WEBHOOK_ID }", 
        "webhook_event": { body } 
    }}'''

    # Get OAuth2 token
    auth_resp = requests.post(
        f"{PAYPAL_BASE}/v1/oauth2/token",
        auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET),
        data={"grant_type": "client_credentials"}
    )
    access_token = auth_resp.json()["access_token"]

    # Call verification API
    verify_resp = requests.post(
        f"{PAYPAL_BASE}/v1/notifications/verify-webhook-signature",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}"
        },
        data=payload
    )

    result = verify_resp.json()
    return result.get("verification_status") == "SUCCESS"


def custom_sig_verify(gcp_email, amount, custom_sig):

    SHARED_SECRET = os.environ['PAYPAL_SHARED_SECRET']

    hash_me = f'{gcp_email}|{amount}|{SHARED_SECRET}'
    m = hashlib.sha256()
    m.update(hash_me.encode())
    sig = m.hexdigest()

    return sig == custom_sig


def add_to_google_group(member_key, mode):  
    with build('cloudidentity', 'v1') as service:
        membership = {
          "preferredMemberKey": {
            "id": member_key
          },
          "roles" : {
            "name" : "MEMBER",
          }
        }

        if mode == 'live':
            group_id = os.environ['GOOGLE_GROUP_ID']
        else:
            group_id = os.environ['SANDBOX_GOOGLE_GROUP_ID']

        response = service.groups().memberships().create(parent=f"groups/{group_id}", body=membership).execute()


# https://stackoverflow.com/a/57092533
def delegated_credentials(credentials, subject, scopes):

    TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'

    try:
        # If we are using service account credentials from json file
        # this will work
        updated_credentials = credentials.with_subject(subject).with_scopes(scopes)
    except AttributeError:
        # This exception is raised if we are using GCE default credentials

        request = gauthtransportrequests.Request()

        # Refresh the default credentials. This ensures that the information
        # about this account, notably the email, is populated.
        credentials.refresh(request)

        # Create an IAM signer using the default credentials.
        signer = iam.Signer(
            request,
            credentials,
            credentials.service_account_email
        )

        # Create OAuth 2.0 Service Account credentials using the IAM-based
        # signer and the bootstrap_credential's service account email.
        updated_credentials = service_account.Credentials(
            signer,
            credentials.service_account_email,
            TOKEN_URI,
            scopes=scopes,
            subject=subject
        )
    except Exception:
        raise

    return updated_credentials


# https://developers.google.com/workspace/gmail/api/guides/sending#python
def send_email(to_emails, subject, content):

    SCOPES=["https://www.googleapis.com/auth/gmail.send"]
    GSUITE_ADMIN_USER = os.environ.get('GSUITE_ADMIN_USER')

    creds, _ = default()
    creds = delegated_credentials(creds, GSUITE_ADMIN_USER, SCOPES) 
    
    from_email = os.environ["FROM_EMAIL"]
    
    service = build("gmail", "v1", credentials = creds)

    message = EmailMessage()
    message.set_content(content, subtype="html")
    
    print(to_emails)
    message["To"] = ", ".join(to_emails)
    message["From"] = from_email
    message["Subject"] = subject
    encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    create_message = {"raw": encoded_message}

    send_message = (
        service.users()
        .messages()
        .send(userId="me", body=create_message)
        .execute()
    )
