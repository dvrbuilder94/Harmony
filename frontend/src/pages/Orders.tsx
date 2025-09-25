import { useState } from 'react'
import { fetchOrders, exportOrdersCsvUrl, type Order, getToken } from '../api'

export default function Orders() {
  const [status, setStatus] = useState('')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [page, setPage] = useState(1)
  const [perPage] = useState(20)
  const [list, setList] = useState<Order[]>([])
  const [loading, setLoading] = useState(false)
  const [kpis, setKpis] = useState({ total: 0, count: 0, avg: 0 })

  const loadOrders = async (pg = 1) => {
    setLoading(true)
    try {
      const data = await fetchOrders({ page: pg, per_page: perPage, status, date_from: from, date_to: to })
      setList(data.orders)
      setPage(pg)
      const total = data.orders.reduce((s, o) => s + (o.total_amount || 0), 0)
      const count = data.orders.length
      setKpis({ total, count, avg: count ? total / count : 0 })
    } finally {
      setLoading(false)
    }
  }

  const exportCsv = () => {
    window.open(exportOrdersCsvUrl({ status, date_from: from, date_to: to }), '_blank')
  }

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Órdenes</h1>
      <div className="flex gap-2 mb-3">
        <input className="border p-2 rounded" placeholder="estado (paid/cancelled)" value={status} onChange={e => setStatus(e.target.value)} />
        <input className="border p-2 rounded" type="date" value={from} onChange={e => setFrom(e.target.value)} />
        <input className="border p-2 rounded" type="date" value={to} onChange={e => setTo(e.target.value)} />
        <button className="bg-gray-900 text-white px-4 py-2 rounded" onClick={() => loadOrders(1)} disabled={loading || !getToken()}>Buscar</button>
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
  )
}

