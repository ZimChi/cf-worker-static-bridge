
# cf-worker-static-bridge

### Project Description
A Cloudflare Worker serving as a secure, serverless backend for an
implementation of Forte Checkout on a static open source GitHub Page. It bridges the
architectural gap between static hosting and dynamic payment processing.

### Core Functionality
* Encrypted Secret Management: Maintains Forte API credentials
  (access IDs, merchant IDs, and secret keys) as encrypted secrets within
  the secure Cloudflare environment.
* Environment Proxy: Uses secrets to generates tokens necessary for the static
  site to validate information and initialize the secure portal to Forte.
* Payment Orchestration: Generates secure, client-facing payment links
  that route users to the static checkout interface.
* Request Handling: Validates payment requests, performs server-side token
  encryption and decryption, and verifies transaction integrity.

### Security Model
* This application maintains a security posture aligned with PCI-DSS and NACHA standards. At no time does the system store, transmit, or touch sensitive financial data such as credit card numbers, banking account details, or other sensitive financial information.

* It further adheres to a "Zero-Exposure" policy in regards to sensitive API credentials which are managed as encrypted Cloudflare Environment Secrets.


### Payment Workflow

1. Link Generation:
   Invoice details are provided via POST to the / endpoint, protected by basic HTTP authentication. The worker encrypts these details with a secret key and returns a URL containing the plain text parameters along with the encrypted token.

2. Client Arrival:
   The customer accesses the provided URL, and the static GitHub Pages site captures the parameters via client-side JavaScript.

3. Validation Request:
   The static page’s inline JavaScript sends the parameters and the encrypted token to the worker. The worker decrypts the token using stored secrets, compares the decrypted values against the provided parameters, and performs a state check to ensure the invoice remains unprocessed.

4. Authorization & Rendering:
   Upon validation, the worker returns a 200 OK status to the frontend along with other Forte-specific fields required for triggering the initialization of the Forte Checkout widget.

5. Secure Handoff:
   The widget renders a Forte payment button which is managed entirely by the Forte Checkout API. This API autonomously opens its own logic involving an iframe so that the client's financial details are entered directly into the Forte portal.

6. Resolution:
   When the transaction within the Forte iframe portal is finalized, the portal closes, and the customer receives a confirmation message on the static site.

### Development Stack
  * Runtime: Cloudflare Workers
  * Persistence: Cloudflare KV
  * Language: TypeScript
  * Environment: Node 22
  * Deployment: Wrangler CLI

### Configuration Requirements
The following environment variables must be configured within your Cloudflare project settings to ensure proper functionality and security:

  * **AES_ENCRYPTION_KEY**: A secure key used for encrypting and validating payment tokens.
  * **FORTE_API_ACCESS_ID**: Your unique Forte API access ID.
  * **FORTE_ENV**: Defines the operating environment (e.g., "production" or not).
  * **FORTE_LOCATION_ID**: The specific Forte location ID associated with your account.
  * **FORTE_MERCHANT_ID**: Your assigned Forte merchant account ID.
  * **FORTE_SECURE_KEY**: Your unique Forte API secret key.
  * **FRONTEND_BASE_URL**: The base URL for your frontend application.
  * **BASIC_AUTH_USER**: Username for basic authentication.
  * **BASIC_AUTH_PASS**: Password for basic authentication.
