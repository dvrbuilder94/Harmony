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

export async function syncMeli(params?: { days_back?: number; mode?: 'recent' | 'search'; debug?: boolean }): Promise<any> {
  if ((import.meta as any).env?.VITE_MOCK === 'true') {
    return { data: { orders: [
      { order_id: 'MOCK-1', total_amount: 10000, status: 'paid', date_created: new Date().toISOString(), items: [{ title: 'Producto demo', quantity: 1, unit_price: 10000 }] },
      { order_id: 'MOCK-2', total_amount: 25000, status: 'paid', date_created: new Date().toISOString(), items: [{ title: 'Otro demo', quantity: 2, unit_price: 12500 }] }
    ] } }
  }
  const qs = new URLSearchParams()
  if (params?.days_back) qs.set('days_back', String(params.days_back))
  if (params?.mode) qs.set('mode', params.mode)
  if (params?.debug) qs.set('debug', 'true')
  const res = await fetch(`${getApiBase()}/api/meli/sync${qs.toString() ? `?${qs.toString()}` : ''}`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${getToken()}` }
  })
  if (!res.ok) throw new Error('Sync failed')
  return res.json()
}

export async function getMeliCreds(): Promise<{ credentials: any | null }> {
  if ((import.meta as any).env?.VITE_MOCK === 'true') {
    return { credentials: { client_id: 'mock', redirect_uri: 'https://example.com/auth/meli/callback' } }
  }
  const res = await fetch(`${getApiBase()}/integrations/meli/credentials`, {
    headers: { 'Authorization': `Bearer ${getToken()}` }
  })
  if (!res.ok) throw new Error('Failed to load credentials')
  const json = await res.json()
  return json.data
}

export type Order = {
  id: string
  order_id: string
  date_created?: string
  currency_id?: string
  total_amount: number
  status?: string
  buyer_nickname?: string
}

export async function fetchOrders(params: { page?: number; per_page?: number; status?: string; date_from?: string; date_to?: string }): Promise<{ orders: Order[]; pagination: any }> {
  if ((import.meta as any).env?.VITE_MOCK === 'true') {
    const orders = [
      { id: '1', order_id: 'MOCK-1', total_amount: 10000, status: 'paid', date_created: new Date().toISOString() },
      { id: '2', order_id: 'MOCK-2', total_amount: 25000, status: 'paid', date_created: new Date().toISOString() },
    ]
    return { orders, pagination: { page: 1, per_page: 50, total: orders.length, pages: 1 } }
  }
  const qs = new URLSearchParams()
  if (params.page) qs.set('page', String(params.page))
  if (params.per_page) qs.set('per_page', String(params.per_page))
  if (params.status) qs.set('status', params.status)
  if (params.date_from) qs.set('date_from', params.date_from)
  if (params.date_to) qs.set('date_to', params.date_to)
  const res = await fetch(`${getApiBase()}/api/orders?${qs.toString()}`, {
    headers: { 'Authorization': `Bearer ${getToken()}` }
  })
  if (!res.ok) throw new Error('Failed to fetch orders')
  const json = await res.json()
  return json.data
}

export function exportOrdersCsvUrl(params: { status?: string; date_from?: string; date_to?: string }): string {
  const qs = new URLSearchParams()
  if (params.status) qs.set('status', params.status)
  if (params.date_from) qs.set('date_from', params.date_from)
  if (params.date_to) qs.set('date_to', params.date_to)
  return `${getApiBase()}/api/orders/export.csv?${qs.toString()}`
}
