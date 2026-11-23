const PUBLIC_CLIENT_APP_TYPES = ["spa", "native"];

/**
 * A client is treated as public when it does not authenticate at the token
 * endpoint (token_endpoint_auth_method "none") or is a SPA / native app.
 */
function isPublicClient(app) {
  if (app.token_endpoint_auth_method === "none") return true;
  return PUBLIC_CLIENT_APP_TYPES.includes(app.app_type);
}

/** "name (client_id)" when the client has an id, otherwise just the name. */
function formatClientName(app) {
  return app.client_id ? app.name.concat(` (${app.client_id})`) : app.name;
}

module.exports = { PUBLIC_CLIENT_APP_TYPES, isPublicClient, formatClientName };
