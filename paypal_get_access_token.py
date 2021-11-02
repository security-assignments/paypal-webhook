'''
Test file, practicing generating an access token without using the (deprecated) paypal python library.
'''

# curl -v https://api-m.sandbox.paypal.com/v1/oauth2/token \
#   -H "Accept: application/json" \
#   -H "Accept-Language: en_US" \
#   -u "client_id:secret" \
#   -d "grant_type=client_credentials"

from dotenv import load_dotenv
import requests
import os

load_dotenv()

API_URL = 'https://api-m.sandbox.paypal.com'

response = requests.post(f'{API_URL}/v1/oauth2/token',
        auth=(os.environ['PAYPAL_SANDBOX_CLIENT_ID'], os.environ['PAYPAL_SANDBOX_CLIENT_SECRET']),
        data={'grant_type':'client_credentials'})

# import pdb; pdb.set_trace()

data = response.json()
auth_header_value = "Bearer " + data['access_token']
headers = {'Authorization': auth_header_value }

response = requests.get(f'{API_URL}/v1/notifications/webhooks', headers = headers)
import pdb; pdb.set_trace()
