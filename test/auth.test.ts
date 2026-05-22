import { it, expect, vi, beforeEach } from 'vitest';
import { hasExceededFailedAuthLimit, isTokenVerified, isAuthenticated } from '../src/auth_modules';

// Mock KV store
let kvStore: Map<string, string>;
const mockKv = {
  get: vi.fn((key: string) => Promise.resolve(kvStore.get(key) || null)),
  put: vi.fn((key: string, value: string) => {
    kvStore.set(key, value);
    return Promise.resolve();
  }),
  delete: vi.fn((key: string) => {
    kvStore.delete(key);
    return Promise.resolve();
  }),
};

const mockC = {
  env: { RATE_LIMIT_KV: mockKv },
  req: { header: vi.fn() }
};

beforeEach(() => {
  kvStore = new Map();
  vi.clearAllMocks();
});

it('hasExceededFailedAuthLimit returns true when count > 3', async () => {
  kvStore.set('fail:1.2.3.4', '4');
  const result = await hasExceededFailedAuthLimit(mockC, '1.2.3.4');
  expect(result).toBe(true);
});

it('isTokenVerified clears KV on success', async () => {
  kvStore.set('fail:1.2.3.4', '1');
  const decoded = { orderNumber: '1', amount: '100', invoiceDate: '2026-05-22' };
  const params = { orderNumber: '1', amount: '100', invoiceDate: '2026-05-22' };

  const result = await isTokenVerified(decoded, params, mockC, '1.2.3.4');

  expect(result).toBe(true);
  expect(mockKv.delete).toHaveBeenCalledWith('fail:1.2.3.4');
});

it('isAuthenticated fails and increments KV on wrong credentials', async () => {
  mockC.env.BASIC_AUTH_USER = 'user';
  mockC.env.BASIC_AUTH_PASS = 'pass';
  // "user:wrong" in base64
  mockC.req.header.mockReturnValue('Basic dXNlcjp3cm9uZw==');

  const result = await isAuthenticated(mockC, '1.2.3.4');

  expect(result).toBe(false);
  expect(mockKv.put).toHaveBeenCalledWith('fail:1.2.3.4', '1', { expirationTtl: 60 });
});
