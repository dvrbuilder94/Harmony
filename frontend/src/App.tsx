import { useEffect, useState } from 'react'
import { Route, Routes } from 'react-router-dom'
import { getApiBase } from './api'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Orders from './pages/Orders'
import SyncPage from './pages/Sync'
import Settings from './pages/Settings'

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
  useEffect(() => {
    fetch(`${api}/health`).then(r => r.json()).then(setHealth).catch(() => setHealth(null))
  }, [api])
  return (
    <div>
      <h1 className="text-2xl font-bold">SalesHarmony</h1>
      <p className="text-gray-600">Plataforma de conciliación de ventas</p>
      <div className="mt-4">
        <pre className="bg-gray-100 p-3 rounded text-sm overflow-auto">{JSON.stringify(health, null, 2)}</pre>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/orders" element={<Orders />} />
        <Route path="/sync" element={<SyncPage />} />
        <Route path="/settings" element={<Settings />} />
      </Routes>
    </Layout>
  )
}

