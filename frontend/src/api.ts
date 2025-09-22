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
  const res = await fetch(`${getApiBase()}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  })
  if (!res.ok) throw new Error('Login failed')
  return res.json()
}

export async function getMeliAuthUrl(): Promise<string> {
  const res = await fetch(`${getApiBase()}/auth/meli/url`, {
    headers: { 'Authorization': `Bearer ${getToken()}` }
  })
  if (!res.ok) throw new Error('Failed to get auth URL')
  const json = await res.json()
  return json.data.auth_url
}

export async function syncMeli(): Promise<any> {
  const res = await fetch(`${getApiBase()}/api/meli/sync`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${getToken()}` }
  })
  if (!res.ok) throw new Error('Sync failed')
  return res.json()
}
