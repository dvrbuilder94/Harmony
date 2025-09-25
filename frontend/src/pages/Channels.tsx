import { useEffect, useState } from 'react'
import { getMeliAuthUrl, syncMeli, getToken, getMeliCreds } from '../api'

export default function Channels() {
  const [loading, setLoading] = useState(false)
  const [creds, setCreds] = useState<any>(null)
  const [statusMsg, setStatusMsg] = useState<string>('')

  useEffect(() => {
    if (!getToken()) return
    getMeliCreds().then(d => setCreds(d.credentials)).catch(() => setCreds(null))
  }, [])

  const connectMeli = async () => {
    const url = await getMeliAuthUrl()
    window.open(url, '_blank')
  }

  const doSync = async () => {
    setLoading(true)
    try {
      const json = await syncMeli()
      if (json.data && typeof json.data.fetched !== 'undefined') {
        setStatusMsg(`Mercado Libre conectado. Órdenes obtenidas: ${json.data.fetched}. Guardadas: ${json.data.saved ?? 0}`)
      } else if (json.data && json.data.orders) {
        setStatusMsg(`Mercado Libre conectado. Órdenes en respuesta: ${json.data.orders.length}`)
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold mb-2">Canales</h1>
      <p className="text-gray-600 mb-4">Configura y sincroniza canales como Mercado Libre.</p>

      <div className="border rounded p-4 max-w-xl">
        <div className="font-semibold mb-2">Mercado Libre</div>
        <div className="text-sm text-gray-600 mb-2">Estado: {creds ? 'Credenciales configuradas' : 'Sin credenciales (configura en Configuración)'}</div>
        <div className="flex gap-2">
          <button className="bg-indigo-600 text-white px-4 py-2 rounded disabled:opacity-50" onClick={connectMeli} disabled={!getToken() || !creds}>Conectar</button>
          <button className="bg-emerald-600 text-white px-4 py-2 rounded disabled:opacity-50" onClick={doSync} disabled={!getToken()}>Sincronizar</button>
        </div>
        {statusMsg && <div className="mt-3 text-sm text-emerald-700">{statusMsg}</div>}
      </div>
    </div>
  )
}

