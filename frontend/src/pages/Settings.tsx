import { useEffect, useState } from 'react'
import { getApiBase, getToken } from '../api'

export default function Settings() {
  const [me, setMe] = useState<any>(null)
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [redirectUri, setRedirectUri] = useState('')
  const [siteId, setSiteId] = useState('MLC')
  const [loading, setLoading] = useState(false)
  useEffect(() => {
    if (!getToken()) return
    fetch(`${getApiBase()}/auth/me`, { headers: { Authorization: `Bearer ${getToken()}` } })
      .then(r => r.json()).then(json => setMe(json.data)).catch(() => {})
    fetch(`${getApiBase()}/integrations/meli/credentials`, { headers: { Authorization: `Bearer ${getToken()}` } })
      .then(r => r.json()).then(json => {
        const c = json.data?.credentials
        if (c) {
          setClientId(c.client_id || '')
          setRedirectUri(c.redirect_uri || '')
          setSiteId(c.site_id || 'MLC')
        }
      }).catch(() => {})
  }, [])
  const saveCreds = async () => {
    setLoading(true)
    try {
      const res = await fetch(`${getApiBase()}/integrations/meli/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` },
        body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri, site_id: siteId })
      })
      if (!res.ok) throw new Error('save failed')
      alert('Credenciales guardadas')
      setClientSecret('')
    } catch {
      alert('No se pudo guardar')
    } finally {
      setLoading(false)
    }
  }
  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Configuración</h1>
      <pre className="bg-gray-100 p-3 rounded text-sm overflow-auto">{JSON.stringify(me, null, 2)}</pre>
      <h2 className="text-lg font-semibold mt-6 mb-2">Integraciones: Mercado Libre</h2>
      <p className="text-sm text-gray-600 mb-2">La configuración de credenciales permite conectar el canal en la sección “Canales”.</p>
      <div className="grid gap-2 max-w-xl">
        <input className="border p-2 rounded" placeholder="Client ID" value={clientId} onChange={e=>setClientId(e.target.value)} />
        <input className="border p-2 rounded" placeholder="Client Secret" type="password" value={clientSecret} onChange={e=>setClientSecret(e.target.value)} />
        <input className="border p-2 rounded" placeholder="Redirect URI" value={redirectUri} onChange={e=>setRedirectUri(e.target.value)} />
        <input className="border p-2 rounded" placeholder="Site ID (MLC)" value={siteId} onChange={e=>setSiteId(e.target.value)} />
        <button className="bg-gray-900 text-white px-4 py-2 rounded disabled:opacity-50" onClick={saveCreds} disabled={loading}>Guardar credenciales</button>
      </div>
    </div>
  )
}

