// Simple in-memory rate limiter — resets on function cold start
// Netlify functions are stateless so this limits bursts within a single warm instance
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 10; // max 10 requests per IP per minute

// Private/internal IP ranges to block (SSRF protection)
const BLOCKED_HOSTNAMES = [
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
];

const BLOCKED_IP_PREFIXES = [
  '10.',
  '172.16.', '172.17.', '172.18.', '172.19.',
  '172.20.', '172.21.', '172.22.', '172.23.',
  '172.24.', '172.25.', '172.26.', '172.27.',
  '172.28.', '172.29.', '172.30.', '172.31.',
  '192.168.',
  '169.254.', // link-local
  '100.64.',  // shared address space
];

function isBlockedHost(hostname) {
  if (BLOCKED_HOSTNAMES.includes(hostname.toLowerCase())) return true;
  if (BLOCKED_IP_PREFIXES.some(prefix => hostname.startsWith(prefix))) return true;
  return false;
}

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    rateLimitMap.set(ip, { windowStart: now, count: 1 });
    return true;
  }
  if (entry.count >= RATE_LIMIT_MAX) return false;
  entry.count++;
  return true;
}

exports.handler = async function(event) {
  // Get client IP
  const ip = (event.headers && (
    event.headers['x-forwarded-for'] ||
    event.headers['x-nf-client-connection-ip'] ||
    event.headers['client-ip'] ||
    'unknown'
  )).split(',')[0].trim();

  // Rate limit check
  if (!checkRateLimit(ip)) {
    return {
      statusCode: 429,
      body: JSON.stringify({ error: 'Too many requests. Please wait a moment before scanning again.' })
    };
  }

  const rawUrl = event.queryStringParameters && event.queryStringParameters.url;
  if (!rawUrl) {
    return { statusCode: 400, body: JSON.stringify({ error: 'No URL provided' }) };
  }

  // Validate URL structure
  let parsedUrl;
  try {
    parsedUrl = new URL(rawUrl);
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Invalid URL format' }) };
  }

  // Only allow HTTP and HTTPS
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Only HTTP and HTTPS URLs are supported' }) };
  }

  // SSRF protection — block private/internal hosts
  const hostname = parsedUrl.hostname;
  if (isBlockedHost(hostname)) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'This URL is not accessible' })
    };
  }

  // Block non-standard ports that could indicate internal services
  const port = parsedUrl.port;
  if (port && !['80', '443', '8080', '8443', ''].includes(port)) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Non-standard ports are not supported' })
    };
  }

  try {
    const response = await fetch(parsedUrl.href, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; UptickScanner/1.0)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(12000)
    });

    if (!response.ok) {
      return {
        statusCode: response.status,
        body: JSON.stringify({ error: 'Site returned ' + response.status })
      };
    }

    // Limit response size to 2MB to prevent memory abuse
    const contentLength = response.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > 2 * 1024 * 1024) {
      return {
        statusCode: 413,
        body: JSON.stringify({ error: 'Page is too large to scan' })
      };
    }

    const html = await response.text();

    // Truncate if still too large
    const truncated = html.length > 500000 ? html.substring(0, 500000) : html;

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({ contents: truncated })
    };
  } catch (e) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: e.message || 'Fetch failed' })
    };
  }
};
