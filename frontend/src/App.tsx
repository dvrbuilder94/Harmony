import { useEffect, useState } from 'react'
import { Link, Route, Routes, useNavigate } from 'react-router-dom'

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
    <div className="p-6">
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

