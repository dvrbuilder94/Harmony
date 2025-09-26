import { useEffect, useState } from 'react'
import { getApiBase, getToken } from '../api'

export default function Conciliation() {
  const [kpis, setKpis] = useState<{ total_payouts:number; conciliations:number; percent:number } | null>(null)
  const [payouts, setPayouts] = useState<any[]>([])
  const [loading, setLoading] = useState(false)

  const loadKpis = async () => {
    const r = await fetch(`${getApiBase()}/api/conciliation/kpis`, { headers: { Authorization: `Bearer ${getToken()}` } })
    const j = await r.json()
    setKpis(j.data)
  }

  const loadPayouts = async () => {
    const r = await fetch(`${getApiBase()}/api/payouts`, { headers: { Authorization: `Bearer ${getToken()}` } })
    const j = await r.json()
    setPayouts(j.data?.payouts || [])
  }

  useEffect(() => {
    if (!getToken()) return
    loadKpis(); loadPayouts()
  }, [])

  const seedBank = async () => {
    setLoading(true)
    try {
      await fetch(`${getApiBase()}/admin/seed/bank`, { method:'POST', headers: { 'Content-Type':'application/json', Authorization: `Bearer ${getToken()}` } })
      await autoConciliate()
      await loadKpis(); await loadPayouts()
    } finally { setLoading(false) }
  }

  const autoConciliate = async () => {
    await fetch(`${getApiBase()}/api/conciliation/auto`, { method:'POST', headers: { Authorization: `Bearer ${getToken()}` } })
  }

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Conciliación</h1>
      {kpis && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div className="border rounded p-4"><div className="text-sm text-gray-500">Payouts</div><div className="text-xl font-semibold">{kpis.total_payouts}</div></div>
          <div className="border rounded p-4"><div className="text-sm text-gray-500">Conciliaciones</div><div className="text-xl font-semibold">{kpis.conciliations}</div></div>
          <div className="border rounded p-4"><div className="text-sm text-gray-500">% Conciliado</div><div className="text-xl font-semibold">{kpis.percent}%</div></div>
        </div>
      )}
      <div className="flex gap-2 mb-4">
        <button className="bg-emerald-600 text-white px-4 py-2 rounded disabled:opacity-50" onClick={seedBank} disabled={loading}>Seed banco + Conciliar</button>
        <button className="bg-gray-700 text-white px-4 py-2 rounded" onClick={async ()=>{await autoConciliate(); await loadKpis();}}>Conciliar automático</button>
      </div>
      <div className="overflow-auto border rounded">
        <table className="min-w-full text-sm">
          <thead className="bg-gray-50">
            <tr>
              <th className="text-left p-2">Payout ID</th>
              <th className="text-left p-2">Order</th>
              <th className="text-left p-2">Canal</th>
              <th className="text-right p-2">Monto</th>
              <th className="text-left p-2">Fecha payout</th>
            </tr>
          </thead>
          <tbody>
            {payouts.map((p:any) => (
              <tr key={p.payout_id} className="border-t">
                <td className="p-2">{p.payout_id}</td>
                <td className="p-2">{p.order_external_id}</td>
                <td className="p-2">{p.channel}</td>
                <td className="p-2 text-right">{p.amount?.toFixed(2)}</td>
                <td className="p-2">{p.paid_out_at || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

