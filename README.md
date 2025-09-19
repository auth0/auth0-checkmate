# Auth0 Checkmate

**Auth0 Checkmate** is a command-line utility that performs configuration checks on your Auth0 tenant. It helps ensure your tenant is securely and correctly configured by validating key settings and generating a detailed report.

---

## 🚀 Features

- Validates your Auth0 tenant configuration
- Generates comprehensive audit reports
- Simple and intuitive CLI interface

---

## ⚠️ Auth0 Management API Use Notice

This tool makes use of the **Auth0 Management API**, which **consumes your tenant’s [rate limits](https://auth0.com/docs/troubleshoot/customer-support/operational-policies/rate-limit-policy/rate-limit-configurations)**. Use it thoughtfully to avoid throttling.

Checkmate for Auth0 is designed to provide visibility into its behavior through your Auth0 tenant's [log events](https://auth0.com/docs/deploy-monitor/logs). Tracking its use is important for monitoring and debugging purposes. You can track its use in several ways, including:

-  The `User-Agent` string in the HTTP request header, which will have a value in the form of `${packageName}/${packageVersion}` (e.g. `auth0-checkmate/1.2.14`). Keep in mind that if the `User-Agent` string is modified on the client side, then Checkmate for Auth0 usage cannot be tracked this way.
- The `client_name` and `scopes` assigned to Checkmate when configuring initial access
- `seccft` events (Successful exchange of Access Token for a Client Credentials Grant) in Auth0 logs

As an example, Checkmate activity might result in a log entry like the one shown below. Each field in the log entry provides valuable information for troubleshooting or auditing, such as the `client_name` identifying the application, the `scope` showing granted permissions, and the `user_agent` indicating the tool version used.

```json
{
  "date": "2025-08-05T19:19:43.071Z",
  "type": "seccft",
  "description": "Client Credentials for Access Token",
  "connection_id": "",
  "client_id": "{CHECKMATE_CLIENT_ID}",
  "client_name": "{CHECKMATE_CLIENT_NAME}",
  "ip": "{REQUEST_IP}",
  "client_ip": "{REQUEST_IP}",
  "user_agent": "{CHECKMATE_USER_AGENT}",
  "hostname": "{TENANT_HOSTNAME}",
  "user_id": "",
  "user_name": "",
  "audience": "https://{TENANT_HOSTNAME}/api/v2/",
  "scope": "{CHECKMATE_SCOPES}",
  "$event_schema": {
    "version": "1.0.0"
  },
  "environment_name": "{AUTH0_ENVIRONMENT}",
  "log_id": "{LOG_ID}",
  "tenant_name": "{AUTH0_TENANT}",
  "_id": "{ID}",
  "isMobile": false,
  "location_info": {},
  "id": "{ID}"
}
```

---

## 📦 Prerequisites

- [Node.js](https://nodejs.dev/) **v20.18.3 or higher**
- A valid [Auth0 tenant](https://auth0.com/)

---

## 🛠️ Installation Options

### Option 1 – Global Installation

Install Auth0 Checkmate globally to use it as a standalone CLI tool:

```bash
npm install -g @auth0/auth0-checkmate
```

Then run it with:

```bash
a0checkmate
```

Follow the interactive prompts to get started.

---

### Option 2 – Run from Source

1. **Clone the repository:**

   ```bash
   git clone https://github.com/auth0/auth0-checkmate
   ```

2. **Navigate into the project folder:**

   ```bash
   cd auth0-checkmate
   ```

3. **Install dependencies:**

   ```bash
   npm install
   ```

4. **Run the tool:**

   ```bash
   npm start
   ```

---

## 🔐 Auth0 Setup Instructions

To use Auth0 Checkmate, you need a **dedicated Auth0 Application** to authorize calls to the Management API.

### Create a Machine-to-Machine Application

1. In the Auth0 Dashboard, go to:
   **Applications → Applications**

2. Click **“Create Application”**

3. In the setup form:
   - **Name:** `Auth0 Checkmate` (or similar)
   - **Application Type:** `Machine to Machine Applications`
   - Click **“Create”**

4. On the "Authorize Machine to Machine Application" screen:
   - Select **Auth0 Management API**
   - Grant only the following scopes:

   ```text
   read:tenant_settings
   read:custom_domains
   read:prompts
   read:clients
   read:connections
   read:connections_options
   read:resource_servers
   read:client_grants
   read:roles
   read:branding
   read:email_provider
   read:email_templates
   read:phone_providers
   read:phone_templates
   read:shields
   read:attack_protection
   read:self_service_profiles
   read:guardian_factors
   read:mfa_policies
   read:actions
   read:log_streams
   read:logs
   read:network_acls
   read:event_streams
   ```

5. Click **“Authorize”** to complete setup.

---

## ✅ You're All Set

With your Auth0 application configured and the CLI installed, you’re ready to run **Auth0 Checkmate** and ensure your tenant setup is secure and complete.
