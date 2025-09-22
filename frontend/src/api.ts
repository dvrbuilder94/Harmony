export function getApiBase(): string {
  return (import.meta as any).env?.VITE_API_URL || 'http://localhost:5000'
}

export function getToken(): string | null {
  return localStorage.getItem('token')
}

export function setToken(token: string) {
  localStorage.setItem('token', token)
}

export async function login(email: string, password: string) {
  if ((import.meta as any).env?.VITE_MOCK === 'true') {
    const mock = { data: { access_token: 'mock-token' } }
    setToken('mock-token')
    return mock
  }
  const res = await fetch(`${getApiBase()}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  })
  if (!res.ok) throw new Error('Login failed')
  return res.json()
}

export async function getMeliAuthUrl(): Promise<string> {
  if ((import.meta as any).env?.VITE_MOCK === 'true') {
    return 'https://example.com/mock-auth'
  }
  const res = await fetch(`${getApiBase()}/auth/meli/url`, {
    headers: { 'Authorization': `Bearer ${getToken()}` }
  })
  if (!res.ok) throw new Error('Failed to get auth URL')
  const json = await res.json()
  return json.data.auth_url
}

export async function syncMeli(): Promise<any> {
  if ((import.meta as any).env?.VITE_MOCK === 'true') {
    return { data: { orders: [
      { order_id: 'MOCK-1', total_amount: 10000, status: 'paid', date_created: new Date().toISOString(), items: [{ title: 'Producto demo', quantity: 1, unit_price: 10000 }] },
      { order_id: 'MOCK-2', total_amount: 25000, status: 'paid', date_created: new Date().toISOString(), items: [{ title: 'Otro demo', quantity: 2, unit_price: 12500 }] }
    ] } }
  }
  const res = await fetch(`${getApiBase()}/api/meli/sync`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${getToken()}` }
  })
  if (!res.ok) throw new Error('Sync failed')
  return res.json()
}
