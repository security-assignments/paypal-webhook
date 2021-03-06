# paypal-webook

Set env vars:

* `SENDGRID_FROM_EMAIL` -- the from-address for the email sendgrid will send
* `SUPPORT_EMAIL` -- email address for customers to use for support requests
* `GOOGLE_GROUP_ID` -- id number for the google group
* `GOOGLE_GROUP_NAME` -- name (email address) identifying the google group
* `SANDBOX_GOOGLE_GROUP_ID` -- id number for the sandboxgoogle group
* `SANDBOX_GOOGLE_GROUP_NAME` -- name (email address) identifying the sandbox google group
* `PAYPAL_WEBHOOK_ID_SANDBOX`
* `PAYPAL_WEBHOOK_ID_LIVE`
* `SENDGRID_EMAIL_API_KEY` -- the sendgrid secret api key. Set this via GCP
  Secrets and expose as an env var.

If paypal mock transactions are being used and paypal validation should be
skipped, set `PAYPAL_MOCK` env var.


## Create paypal webhooks

Using <https://developer.paypal.com>, create a sandbox and live app, and within each,
create a webhook that sends events for PAYMENT.CAPTURE.COMPLETED. Set the webhook ids
as env vars (see above). These ids are needed to verify the webhook event signature.

Set this function's http target as the webhook url. (Chicken and egg, I know!)

Mock transactions sent via the developer portal will not have `custom_id` and
`invoice_id`, although webhooks triggered by transactions generated by
security-assignments.com/store _will_ have these fields.


## Create the target google group

1. On <https://admin.google.com>, set it so that members external to the
organization can be members of the group.
1. Fetch the google group's new id. Use <https://developers.google.com/admin-sdk/directory/reference/rest/v1/groups/list?apix_params=%7B%22customer%22%3A%22my_customer%22%7D> to find it.



## Give the service account access to the google group

Add the service account's email address as an "owner" member of the google group.
This should give the service account permissions to manage group membership.

**Alternatively**, grant GROUP ADMIN role to the service account as follows:

The service account that runs the cloud function needs permissions to manage google
groups for the domain.

Follow this guide: <https://cloud.google.com/identity/docs/how-to/setup#auth-no-dwd>

* The service account "unique id" is the OAuth2 id in the table:
* Use the API Explorer to fetch a list of all roles. Scroll through to find the
  GROUP ADMIN role, and use its id.


## Development

Note that _certain_ (not all) **@example.com** emails will fail if they are
attempted to be added to a google group. I don't know why and I can't discern a
pattern. But adding a legitimate email address hasn't failed on me yet.


### Run locally

```bash
functions_framework --target=main --debug
```

## Deploy

```bash
gcloud beta functions deploy security-assignments-purchase \
  --entry-point do_webhook \
  --allow-unauthenticated \
  --runtime python37 \
  --env-vars-file env.yml \
  --trigger-http \
  --region us-central1 \
  --security-level secure-always \
  --set-secrets 'SENDGRID_EMAIL_API_KEY=SENDGRID_EMAIL_API_KEY:latest,PAYPAL_SHARED_SECRET=PAYPAL_SHARED_SECRET:latest'
```

View trigger-http url (and more info):

```bash
gcloud beta functions describe security-assignments-purchase
```
