
async function getForteUtcTime(): Promise<string> {
  const res = await fetch("https://checkout.forte.net/getUTC?callback=?", {
    headers: {
      "Connection": "close"
    }
  });

  const rawText = (await res.text()).trim();
  let utcTime;
  if (/^\d+$/.test(rawText)) {
    utcTime = rawText;
  } else {
    const match = rawText.match(/\((\d+)\)/);
    utcTime = match ? match[1] : null;
  }
  if (!utcTime) {
    throw new Error("Invalid UTC response from Forte");
  }
  return utcTime;
}

async function checkPaymentStatus(
    orderNumber: string,
    accessID: string,
    secureKey: string,
    locationId: string,
    merchantId: string,
    isProduction: boolean
  ): Promise<boolean> {
  const orgId = `org_${merchantId}`;
  const locId = `loc_${locationId}`;

  const auth = toWindows1252Base64(`${accessID}:${secureKey}`);

  const baseForteUrl = isProduction
    ? "https://api.forte.net/v3"
    : "https://sandbox.forte.net/api/v3" ;

  const url = `${baseForteUrl}/organizations/${orgId}/locations/${locId}/transactions?filter=order_number+eq+${orderNumber}`;

  const response = await fetch(url, {
    method: "GET",
    headers: {
      "Authorization": `Basic ${auth}`,
      "Accept": "application/json",
      "X-Forte-Auth-Organization-Id": orgId,
      "Connection": "close"
    }
  });

  const text = await response.text();
  const data = JSON.parse(text);
  return data.number_results > 0;
}

function toWindows1252Base64(str: string): string {
  const bytes = Uint8Array.from(str, c => c.charCodeAt(0) & 0xFF);
  return btoa(String.fromCharCode(...bytes));
}

export { checkPaymentStatus, getForteUtcTime };
