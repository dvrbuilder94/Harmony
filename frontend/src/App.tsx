import { useEffect, useState } from 'react'
import { Link, Route, Routes } from 'react-router-dom'
import { getApiBase, getToken, setToken, login, getMeliAuthUrl, syncMeli, fetchOrders, exportOrdersCsvUrl, type Order } from './api'

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
  const [list, setList] = useState<Order[]>([])
  const [status, setStatus] = useState<string>('')
  const [from, setFrom] = useState<string>('')
  const [to, setTo] = useState<string>('')
  const [page, setPage] = useState<number>(1)
  const [perPage, setPerPage] = useState<number>(20)
  const [kpis, setKpis] = useState<{ total:number; count:number; avg:number }>({ total: 0, count: 0, avg: 0 })
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
  const loadOrders = async (pg = 1) => {
    setLoading(true)
    try {
      const data = await fetchOrders({ page: pg, per_page: perPage, status, date_from: from, date_to: to })
      setList(data.orders)
      setPage(pg)
      const total = data.orders.reduce((s, o) => s + (o.total_amount || 0), 0)
      const count = data.orders.length
      setKpis({ total, count, avg: count ? total / count : 0 })
    } catch (e) {
      console.error(e)
      alert('No se pudo cargar órdenes')
    } finally {
      setLoading(false)
    }
  }
  const exportCsv = () => {
    window.open(exportOrdersCsvUrl({ status, date_from: from, date_to: to }), '_blank')
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
      <div className="mt-8">
        <h2 className="text-xl font-semibold mb-2">Órdenes (persistidas)</h2>
        <div className="flex gap-2 mb-3">
          <input className="border p-2 rounded" placeholder="estado (paid/cancelled)" value={status} onChange={e => setStatus(e.target.value)} />
          <input className="border p-2 rounded" type="date" value={from} onChange={e => setFrom(e.target.value)} />
          <input className="border p-2 rounded" type="date" value={to} onChange={e => setTo(e.target.value)} />
          <button className="bg-gray-900 text-white px-4 py-2 rounded" onClick={() => loadOrders(1)} disabled={!getToken()}>Buscar</button>
          <button className="bg-gray-600 text-white px-4 py-2 rounded" onClick={exportCsv} disabled={!getToken()}>Exportar CSV</button>
        </div>
        <div className="flex gap-6 mb-3 text-sm text-gray-700">
          <div><span className="font-semibold">Ventas</span>: {kpis.count}</div>
          <div><span className="font-semibold">Bruto</span>: {kpis.total.toFixed(2)}</div>
          <div><span className="font-semibold">Ticket prom.</span>: {kpis.avg.toFixed(2)}</div>
        </div>
        <div className="overflow-auto border rounded">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50">
              <tr>
                <th className="text-left p-2">Order ID</th>
                <th className="text-left p-2">Fecha</th>
                <th className="text-left p-2">Estado</th>
                <th className="text-right p-2">Monto</th>
              </tr>
            </thead>
            <tbody>
              {list.map(o => (
                <tr key={o.id} className="border-t">
                  <td className="p-2">{o.order_id}</td>
                  <td className="p-2">{o.date_created?.slice(0,10)}</td>
                  <td className="p-2">{o.status}</td>
                  <td className="p-2 text-right">{o.total_amount?.toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-3 flex gap-2">
          <button className="px-3 py-1 border rounded" disabled={page<=1} onClick={() => loadOrders(page-1)}>Anterior</button>
          <button className="px-3 py-1 border rounded" onClick={() => loadOrders(page+1)}>Siguiente</button>
        </div>
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

