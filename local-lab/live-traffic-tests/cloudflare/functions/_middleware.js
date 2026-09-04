export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);

  const entry = {
    timestamp: new Date().toISOString(),
    method: request.method,
    path: url.pathname,
    query: url.search || null,
    client_ip: request.headers.get("cf-connecting-ip") || null,
    country: request.headers.get("cf-ipcountry") || null,
    user_agent: request.headers.get("user-agent") || null,
    referer: request.headers.get("referer") || null,
    ray_id: request.headers.get("cf-ray") || null,
  };

  // Logged via console so `wrangler pages deployment tail` can stream it
  // to the local relay that forwards these into Wazuh.
  console.log(JSON.stringify({ cf_lab_request: entry }));

  return context.next();
}
