import { useEffect, useState } from 'react'
import { Link, Route, Routes } from 'react-router-dom'
import { getApiBase, getToken, setToken, login, getMeliAuthUrl, syncMeli } from './api'

function useApiBase() {
  const [base, setBase] = useState<string>('http://localhost:5000')
  useEffect(() => {
    if (import.meta.env.VITE_API_URL) setBase(import.meta.env.VITE_API_URL)
  }, [])
  return base
}

function Home() {
  const api = useApiBase()
  const [health, setHealth] = useState<any>(null)
  const [email, setEmail] = useState('a@a.com')
  const [password, setPassword] = useState('x')
  const [orders, setOrders] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  useEffect(() => {
    fetch(`${api}/health`).then(r => r.json()).then(setHealth).catch(() => setHealth(null))
  }, [api])
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
    try {
      const url = await getMeliAuthUrl()
      window.open(url, '_blank')
    } catch (e) {
      alert('No se pudo obtener la URL de Mercado Libre')
    }
  }
  const doSync = async () => {
    setLoading(true)
    try {
      const json = await syncMeli()
      setOrders(json.data.orders || [])
    } catch (e) {
      alert('Sync falló. ¿Conectaste Mercado Libre?')
    } finally {
      setLoading(false)
    }
  }
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold">SalesHarmony</h1>
      <p className="text-gray-600">Plataforma de conciliación de ventas</p>
      <div className="mt-4">
        <pre className="bg-gray-100 p-3 rounded text-sm overflow-auto">{JSON.stringify(health, null, 2)}</pre>
      </div>
      <div className="mt-6 grid gap-3 max-w-md">
        <input className="border p-2 rounded" placeholder="email" value={email} onChange={e => setEmail(e.target.value)} />
        <input className="border p-2 rounded" placeholder="password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
        <button className="bg-black text-white px-4 py-2 rounded disabled:opacity-50" onClick={doLogin} disabled={loading}>Iniciar sesión</button>
        <button className="bg-indigo-600 text-white px-4 py-2 rounded" onClick={connectMeli} disabled={!getToken()}>Conectar Mercado Libre</button>
        <button className="bg-emerald-600 text-white px-4 py-2 rounded" onClick={doSync} disabled={!getToken()}>Sincronizar Órdenes</button>
      </div>
      {!!orders.length && (
        <div className="mt-6">
          <h2 className="text-xl font-semibold mb-2">Órdenes</h2>
          <pre className="bg-gray-100 p-3 rounded text-sm overflow-auto">{JSON.stringify(orders, null, 2)}</pre>
        </div>
      )}
    </div>
  )
}

export default function App() {
  return (
    <div>
      <nav className="p-4 border-b">
        <Link to="/">Inicio</Link>
      </nav>
      <Routes>
        <Route path="/" element={<Home />} />
      </Routes>
    </div>
  )
}

