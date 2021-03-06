# https://github.com/paypal/PayPal-Python-SDK/blob/master/samples/notification/webhook-events/verify_webhook_events.py
from paypalrestsdk import WebhookEvent
from flask import jsonify
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import os
import hashlib
from dotenv import load_dotenv

load_dotenv()


def do_webhook(request):

    if not "PAYPAL_MOCK" in os.environ:
        paypal_verified = paypal_verify(request)
        if not paypal_verified:
            print(request.headers)
            print(request.get_data().decode('utf-8'))
            raise Exception('Paypal transaction did not verify! See logs.')



    # https://developer.paypal.com/docs/api-basics/notifications/webhooks/notification-messages/
    # https://developer.paypal.com/docs/api/orders/v1/#orders_get
    webhook_event_json = request.get_json()
    gcp_email = webhook_event_json['resource']['invoice_id']
    amount = webhook_event_json['resource']['amount']['value']
    custom_sig = webhook_event_json['resource']['custom_id']
    support_email = os.environ['SUPPORT_EMAIL']
    to_emails = [ gcp_email ]
    extra_message = ''

    if not "PAYPAL_MOCK" in os.environ:
        if 'sandbox' in request.headers.get('Paypal-Cert-Url'):
            mode = 'sandbox'
        else:
            mode = 'live'
    else:
        mode = 'sandbox'


    custom_sig_verified = custom_sig_verify(gcp_email, amount, custom_sig)
    if not custom_sig_verified:

        to_emails.append(support_email)
        extra_message =  (
            f'<br/> Error reason: bad signature.'
            f'<br/> This error has been reported to <strong>{support_email}</strong>. You should receive help soon.'
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
            '<br/>'
            f'<br/> This error has been reported to <strong>{support_email}</strong>. You should receive help soon.'
        )
        result_adverb = "unsuccessfully"
        to_emails.append(support_email)

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
        content += f'{extra_message}'
    # print(content)

    send_email(to_emails, subject, content)

    pass


def paypal_verify(request):
    # The payload body sent in the webhook event
    event_body = request.data.decode('utf-8')
    # Paypal-Transmission-Id in webhook payload header
    transmission_id = request.headers.get('Paypal-Transmission-Id')
    # Paypal-Transmission-Time in webhook payload header
    timestamp = request.headers.get('Paypal-Transmission-Time')

    actual_signature = request.headers.get('Paypal-Transmission-Sig')
    cert_url = request.headers.get('Paypal-Cert-Url')
    auth_algo = request.headers.get('PayPal-Auth-Algo')

    if 'sandbox' in cert_url:
        webhook_id = os.environ['PAYPAL_WEBHOOK_ID_SANDBOX']
    else:
        webhook_id = os.environ['PAYPAL_WEBHOOK_ID_LIVE']

    verified = WebhookEvent.verify(
      transmission_id, timestamp, webhook_id, event_body, cert_url, actual_signature, auth_algo)
    return verified


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


# https://github.com/sendgrid/sendgrid-python/blob/main/use_cases/send_a_single_email_to_multiple_recipients.md
def send_email(to_emails, subject, content):

    message = Mail(
        from_email=os.environ['SENDGRID_FROM_EMAIL'],
        to_emails=to_emails,
        subject=subject,
        html_content=content
    )
    try:
        sg = SendGridAPIClient(os.environ['SENDGRID_EMAIL_API_KEY'])
        response = sg.send(message)
        # print(response.status_code)
        # print(response.body)
        # print(response.headers)
    except Exception as e:
        print(e)
        print(e.body)
