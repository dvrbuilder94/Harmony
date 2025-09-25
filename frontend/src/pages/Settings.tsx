import { useEffect, useState } from 'react'
import { getApiBase, getToken } from '../api'

export default function Settings() {
  const [me, setMe] = useState<any>(null)
  useEffect(() => {
    if (!getToken()) return
    fetch(`${getApiBase()}/auth/me`, { headers: { Authorization: `Bearer ${getToken()}` } })
      .then(r => r.json()).then(json => setMe(json.data)).catch(() => {})
  }, [])
  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Configuración</h1>
      <pre className="bg-gray-100 p-3 rounded text-sm overflow-auto">{JSON.stringify(me, null, 2)}</pre>
    </div>
  )
}

