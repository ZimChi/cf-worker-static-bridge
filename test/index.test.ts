import { describe, it, expect, vi, afterEach} from 'vitest';
import { env } from 'cloudflare:test';
import app from '../src/index';
import * as crypto from '../src/crypto_modules';
import * as auth from '../src/auth_modules';
import * as forte from '../src/forte_modules';



describe('POST /', () => {
  describe('when the rate limit is exceeded', () => {
    it('returns 429 status', async () => {
      vi.spyOn(auth, 'hasExceededFailedAuthLimit').mockResolvedValue(true);

      const res = await app.request('/', { method: 'POST' }, env);

      expect(res.status).toBe(429);
    });
  });

  describe('when the user is unauthorized', () => {
    it('returns 401 status with WWW-Authenticate header', async () => {
      vi.spyOn(auth, 'hasExceededFailedAuthLimit').mockResolvedValue(false);
      vi.spyOn(auth, 'isAuthenticated').mockResolvedValue(false);

      const res = await app.request('/', { method: 'POST' }, env);

      expect(res.status).toBe(401);
      expect(res.headers.get('WWW-Authenticate')).toBe('Basic realm="secure"');
    });
  });

  describe('when fields are missing', () => {
    it('returns 400 status', async () => {
      vi.spyOn(auth, 'hasExceededFailedAuthLimit').mockResolvedValue(false);
      vi.spyOn(auth, 'isAuthenticated').mockResolvedValue(true);

      const res = await app.request('/', {
        method: 'POST',
        body: new FormData() // Missing required fields
      }, env);

      expect(res.status).toBe(400);
    });
  });

  describe('when all checks pass', () => {
    it('returns 200 and a valid payment URL', async () => {
      vi.spyOn(auth, 'hasExceededFailedAuthLimit').mockResolvedValue(false);
      vi.spyOn(auth, 'isAuthenticated').mockResolvedValue(true);

      const amount = '100';
      const invoiceDate = '2026-05-22';
      const orderNumber = '12345';
      const serviceDescription = 'Service';
      const invoiceUrl = 'https://example.com';

      const formData = new FormData();
      formData.append('amount', amount);
      formData.append('invoiceDate', invoiceDate);
      formData.append('orderNumber', orderNumber);
      formData.append('serviceDescription', serviceDescription);
      formData.append('invoiceUrl', invoiceUrl);

      const res = await app.request('/', {
        method: 'POST',
        body: formData
      }, env);

      expect(res.status).toBe(200);

      const data = await res.json();
      expect(data).toHaveProperty('paymentUrl');

      const paymentUrl = new URL(data.paymentUrl);
      expect(paymentUrl.searchParams.get('amount')).toBe(amount);
      expect(paymentUrl.searchParams.get('orderNumber')).toBe(orderNumber);
      expect(paymentUrl.searchParams.get('encryptedToken')).toBeDefined();
    });
  });
});

describe('POST /verify', () => {
  describe('when the rate limit is exceeded', () => {
    it('returns 429 status', async () => {
      vi.spyOn(auth, 'hasExceededFailedAuthLimit').mockResolvedValue(true);

      const res = await app.request('/verify', {
        method: 'POST',
        body: JSON.stringify({ /* payload */ })
      }, env);

      expect(res.status).toBe(429);
    });

    it('does not proceed to decrypt the token', async () => {
      vi.spyOn(auth, 'hasExceededFailedAuthLimit').mockResolvedValue(true);
      const decryptSpy = vi.spyOn(crypto, 'decryptToken');

      await app.request('/verify', { method: 'POST' }, env);

      expect(decryptSpy).not.toHaveBeenCalled();
    });
  });

  describe('when the token is invalid', () => {
    it('returns 401 status', async () => {
      vi.spyOn(auth, 'hasExceededFailedAuthLimit').mockResolvedValue(false);
      vi.spyOn(crypto, 'decryptToken').mockResolvedValue('url|123|100|2026-05-22');
      vi.spyOn(auth, 'isTokenVerified').mockResolvedValue(false);

      const res = await app.request('/verify', {
        method: 'POST',
        body: JSON.stringify({ amount: '1', invoiceDate: '1', orderNumber: '1', encryptedToken: '1' })
      }, env);

      expect(res.status).toBe(401);
    });
  });

  describe('when all checks pass', () => {

    it('returns 200 and correct data', async () => {
      const mockAmount = '100';
      const mockInvoiceDate = '2026-05-22';
      const mockOrderNumber = '12345';
      const mockInvoiceUrl = 'https://example.com';
      const mockUtcTime = '1716373949';
      const mockHmac = 'mocked_hmac_signature';
      const mockEncryptedToken = 'mocked_encrypted_token_string';
      const mockDecryptedToken = `${mockInvoiceUrl}|${mockOrderNumber}|${mockAmount}|${mockInvoiceDate}`;

      vi.spyOn(auth, 'hasExceededFailedAuthLimit').mockResolvedValue(false);
      vi.spyOn(crypto, 'decryptToken').mockResolvedValue(mockDecryptedToken);
      vi.spyOn(auth, 'isTokenVerified').mockResolvedValue(true);
      vi.spyOn(forte, 'checkPaymentStatus').mockResolvedValue(false);
      vi.spyOn(forte, 'getForteUtcTime').mockResolvedValue(mockUtcTime);
      vi.spyOn(crypto, 'generateHmac').mockReturnValue(mockHmac);

      const res = await app.request('/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'CF-Connecting-IP': '127.0.0.1'
        },
        body: JSON.stringify({
          amount: mockAmount,
          invoiceDate: mockInvoiceDate,
          orderNumber: mockOrderNumber,
          encryptedToken: mockEncryptedToken
        })
      }, env);

      expect(res.status).toBe(200);
      const data = await res.json();

      expect(data).toHaveProperty('apiId');
      expect(data).toHaveProperty('locationId');
      expect(data.utcTime).toBe(mockUtcTime);

      expect(data.amount).toBe(mockAmount);
      expect(data.orderNumber).toBe(mockOrderNumber);
      expect(data.decryptedInvoiceUrl).toBe(mockInvoiceUrl);
      expect(data.forteSignature).toBe(mockHmac);
    });
  });
});
