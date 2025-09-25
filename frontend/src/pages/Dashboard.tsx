import { useEffect, useState } from 'react'
import { fetchOrders, type Order, getToken } from '../api'

export default function Dashboard() {
  const [orders, setOrders] = useState<Order[]>([])
  const [kpis, setKpis] = useState<{ total:number; count:number; avg:number }>({ total: 0, count: 0, avg: 0 })

  useEffect(() => {
    if (!getToken()) return
    fetchOrders({ page: 1, per_page: 10 }).then(data => {
      setOrders(data.orders)
      const total = data.orders.reduce((s, o) => s + (o.total_amount || 0), 0)
      const count = data.orders.length
      setKpis({ total, count, avg: count ? total / count : 0 })
    }).catch(() => {})
  }, [])

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Dashboard</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="border rounded p-4"><div className="text-sm text-gray-500">Ventas</div><div className="text-xl font-semibold">{kpis.count}</div></div>
        <div className="border rounded p-4"><div className="text-sm text-gray-500">Bruto</div><div className="text-xl font-semibold">{kpis.total.toFixed(2)}</div></div>
        <div className="border rounded p-4"><div className="text-sm text-gray-500">Ticket prom.</div><div className="text-xl font-semibold">{kpis.avg.toFixed(2)}</div></div>
      </div>
      <h2 className="text-lg font-semibold mb-2">Últimas órdenes</h2>
      {!getToken() && (
        <div className="mb-3 text-sm text-gray-600">Inicia sesión en la sección "Sincronización" para ver tus órdenes.</div>
      )}
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
            {orders.map(o => (
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
    </div>
  )
}

