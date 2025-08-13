import os
import requests
import json
from dotenv import load_dotenv
load_dotenv()

import yaml


env_file = "env.yml"
if os.environ.get("LOCAL_DEV"):
    if os.path.exists(env_file):
        with open(env_file) as f:
            env_vars = yaml.safe_load(f)
        for key, value in env_vars.items():
            os.environ[key] = str(value)



def verify_webhook(headers, body):
    """
    headers: dict from incoming request
    body: raw request data (str), not parsed JSON
    """

    if "sandbox" in headers["Paypal-Cert-Url"]:
        print("mode: sandbox")
        PAYPAL_BASE = "https://api-m.sandbox.paypal.com"
        PAYPAL_CLIENT_ID = os.environ["PAYPAL_SANDBOX_CLIENT_ID"]
        PAYPAL_CLIENT_SECRET = os.environ["PAYPAL_SANDBOX_CLIENT_SECRET"]
        PAYPAL_WEBHOOK_ID = os.environ['PAYPAL_WEBHOOK_ID_SANDBOX']
    else:
        print("mode: live")
        PAYPAL_BASE = "https://api-m.paypal.com"
        PAYPAL_CLIENT_ID = os.environ["PAYPAL_LIVE_CLIENT_ID"]
        PAYPAL_CLIENT_SECRET = os.environ["PAYPAL_LIVE_CLIENT_SECRET"]
        PAYPAL_WEBHOOK_ID = os.environ['PAYPAL_WEBHOOK_ID_LIVE']

    transmission_id = headers["Paypal-Transmission-Id"]
    transmission_time = headers["Paypal-Transmission-Time"]
    transmission_sig = headers["Paypal-Transmission-Sig"]
    cert_url = headers["Paypal-Cert-Url"]
    auth_algo = headers["Paypal-Auth-Algo"]

    # Your configured webhook ID from PayPal dashboard
    webhook_id = PAYPAL_WEBHOOK_ID


    # Get OAuth2 token
    auth_resp = requests.post(
        f"{PAYPAL_BASE}/v1/oauth2/token",
        auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET),
        data={"grant_type": "client_credentials"},
        verify=False
    )
    access_token = auth_resp.json()["access_token"]

    # Prepare verification payload
    payload = f'''{{ 
        "auth_algo": "{ auth_algo }", 
        "cert_url": "{ cert_url }", 
        "transmission_id": "{ transmission_id }", 
        "transmission_sig": "{ transmission_sig }", 
        "transmission_time": "{ transmission_time }", 
        "webhook_id": "{ webhook_id }", 
        "webhook_event": { body } }}
    '''

    # Call verification API

    headers={ "Content-Type": "application/json", "Authorization": f"Bearer {access_token}" }

    verify_resp = requests.post(
        f"{PAYPAL_BASE}/v1/notifications/verify-webhook-signature",
        headers=headers,
        data=payload,
        verify=False
    )

    result = verify_resp.json()
    print(verify_resp)
    print(result)
    return result.get("verification_status") == "SUCCESS"

headers = {
    "Paypal-Transmission-Time": "2025-08-12T22:16:03Z",
    "Paypal-Auth-Version": "v2",
    "Paypal-Auth-Algo": "SHA256withRSA",
    "Paypal-Cert-Url": "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-360caa42-fca2a594-90621ecd",
    "Paypal-Transmission-Sig": "OuagmwtCxeM7Vd/DavQ6rLmfgFuUTSAzybyMBfqkkWLtD9+Rmz+oJC0wCFp+IPB7sLNLJCwIDR4KT7wMkmS7zbc8fcGj6H3xZd7KzE3hJdcpQ7e1RVM8MfH6ycCVr0Jc9nVy7u/N2yRfpRFtzvSoTtUBGmz4tNKLlFqCs3q8PFRqMJp568Z/LJf7zQuYUVp8L0I7MO2Jk+fl0siprl4Dh8Bjv2sD+fLMEiP6WilZVWymltsjO0IijJWlok6IguC6e/aU4Rho4aadwMZ/zzmjRVZLJpH2+O384V2wN9+/Jgk1z/1d2fw9lNEqNXo8x0pDsl0bLnj+dOzLa3pJinBTjQ==",
    "Paypal-Transmission-Id": "ef4d7ca7-77c9-11f0-ae6f-8bd1ddec93b4"
}

body = '{"id":"WH-0T975963F5930404W-9AK51205WN370144T","event_version":"1.0","create_time":"2025-08-12T22:15:53.028Z","resource_type":"capture","resource_version":"2.0","event_type":"PAYMENT.CAPTURE.COMPLETED","summary":"Payment completed for $ 50.0 USD","resource":{"amount":{"value":"50.00","currency_code":"USD"},"seller_protection":{"dispute_categories":["ITEM_NOT_RECEIVED","UNAUTHORIZED_TRANSACTION"],"status":"ELIGIBLE"},"create_time":"2025-08-12T22:15:48Z","custom_id":"096fee8e3edd44e912362411111c38c8afece5b5e8adc5741adb5512fbe37199","payee":{"email_address":"sb-4zmww7093638@business.example.com","merchant_id":"BPTCJFX8LLT2J"},"supplementary_data":{"related_ids":{"order_id":"7ET427038W466131N"}},"update_time":"2025-08-12T22:15:48Z","final_capture":true,"seller_receivable_breakdown":{"paypal_fee":{"value":"2.24","currency_code":"USD"},"gross_amount":{"value":"50.00","currency_code":"USD"},"net_amount":{"value":"47.76","currency_code":"USD"}},"invoice_id":"whatever4@gmail.com","links":[{"method":"GET","rel":"self","href":"https://api.sandbox.paypal.com/v2/payments/captures/9E510401ES1479703"},{"method":"POST","rel":"refund","href":"https://api.sandbox.paypal.com/v2/payments/captures/9E510401ES1479703/refund"},{"method":"GET","rel":"up","href":"https://api.sandbox.paypal.com/v2/checkout/orders/7ET427038W466131N"}],"id":"9E510401ES1479703","status":"COMPLETED"},"links":[{"href":"https://api.sandbox.paypal.com/v1/notifications/webhooks-events/WH-0T975963F5930404W-9AK51205WN370144T","rel":"self","method":"GET"},{"href":"https://api.sandbox.paypal.com/v1/notifications/webhooks-events/WH-0T975963F5930404W-9AK51205WN370144T/resend","rel":"resend","method":"POST"}]}'

body_raw = body

verified = verify_webhook(headers, body_raw)
print(verified)