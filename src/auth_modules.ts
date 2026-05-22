
async function hasExceededFailedAuthLimit(c: any, ip: string): Promise<boolean> {
  const kv = c.env.RATE_LIMIT_KV;
  if (!kv) return false;

  const cacheKey = `fail:${ip}`;
  const currentCountStr = await kv.get(cacheKey);

  if (!currentCountStr) return false;

  const count = parseInt(currentCountStr, 10);

  if (count > 3) {
    console.log(`FAILED_AUTH_LIMIT ip=${ip} count=${count}`);
    return true;
  }

  return false;
}

async function isTokenVerified(decodedToken: Record<string, string>, plaintextParams: Record<string, string>, c: any, ip: string): Promise<boolean> {
  const valid = decodedToken.orderNumber === plaintextParams.orderNumber &&
                decodedToken.amount === plaintextParams.amount &&
                decodedToken.invoiceDate === plaintextParams.invoiceDate;

  if (!valid) {
    await incrementFailureCount(c, ip);
    return false;
  }

  const kv = c.env.RATE_LIMIT_KV;
  if (kv) {
    await kv.delete(`fail:${ip}`);
  }

  return true;
}

async function isAuthenticated(c: any, ip: string): Promise<boolean> {
  const header = c.req.header("Authorization") || "";
  const expectedUser = c.env.BASIC_AUTH_USER || "";
  const expectedPass = c.env.BASIC_AUTH_PASS || "";

  if (!header || !header.startsWith("Basic ")) {
    await incrementFailureCount(c, ip);
    return false;
  }

  try {
    const decoded = atob(header.replace("Basic ", ""));
    const [user, pass] = decoded.split(":");
    const ok = user === expectedUser && pass === expectedPass;

    if (!ok) {
      await incrementFailureCount(c, ip);
      return false;
    }

    // Clear record on successful authentication
    const kv = c.env.RATE_LIMIT_KV;
    if (kv) {
      await kv.delete(`fail:${ip}`);
    }
    return true;
  } catch (err) {
    await incrementFailureCount(c, ip);
    return false;
  }
}

async function incrementFailureCount(c: any, ip: string): Promise<void> {
  const kv = c.env.RATE_LIMIT_KV;
  if (!kv) return;

  const cacheKey = `fail:${ip}`;
  const currentCountStr = await kv.get(cacheKey);
  const currentCount = currentCountStr ? parseInt(currentCountStr, 10) : 0;
  const newCount = currentCount + 1;

  // Cloudflare KV requires a minimum expirationTtl of 60 seconds.
  // Entries will automatically drop off after this window.
  await kv.put(cacheKey, String(newCount), { expirationTtl: 60 });

  console.error(`FAILED_AUTH ip=${ip} count=${newCount}`);
}

export { hasExceededFailedAuthLimit, isAuthenticated, isTokenVerified };
