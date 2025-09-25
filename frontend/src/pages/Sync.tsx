import { useState } from 'react'
import { login, setToken, getToken, getMeliAuthUrl, syncMeli } from '../api'

export default function SyncPage() {
  const [email, setEmail] = useState('a@a.com')
  const [password, setPassword] = useState('x')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<any>(null)

  const doLogin = async () => {
    setLoading(true)
    try {
      const json = await login(email, password)
      setToken(json.data.access_token)
      alert('Login OK')
    } catch (e) {
      alert('Login failed')
    } finally {
      setLoading(false)
    }
  }

  const connectMeli = async () => {
    const url = await getMeliAuthUrl()
    window.open(url, '_blank')
  }

  const doSync = async () => {
    setLoading(true)
    try {
      const json = await syncMeli()
      setResult(json.data)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Sincronización</h1>
      <div className="grid gap-2 max-w-md">
        <input className="border p-2 rounded" placeholder="email" value={email} onChange={e => setEmail(e.target.value)} />
        <input className="border p-2 rounded" placeholder="password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
        <button className="bg-black text-white px-4 py-2 rounded disabled:opacity-50" onClick={doLogin} disabled={loading}>Iniciar sesión</button>
        <button className="bg-indigo-600 text-white px-4 py-2 rounded" onClick={connectMeli} disabled={!getToken()}>Conectar Mercado Libre</button>
        <button className="bg-emerald-600 text-white px-4 py-2 rounded" onClick={doSync} disabled={!getToken()}>Sincronizar Órdenes</button>
      </div>
      {result && (
        <div className="mt-6">
          <h2 className="text-lg font-semibold">Resultado</h2>
          <pre className="bg-gray-100 p-3 rounded text-sm overflow-auto">{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}
    </div>
  )
}

