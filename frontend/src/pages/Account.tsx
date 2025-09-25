import { useState } from 'react'
import { login, setToken } from '../api'

export default function Account() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)

  const doLogin = async () => {
    setLoading(true)
    try {
      const json = await login(email, password)
      setToken(json.data.access_token)
      alert('Login OK')
    } catch {
      alert('Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Cuenta</h1>
      <div className="grid gap-2 max-w-md">
        <input className="border p-2 rounded" placeholder="email" value={email} onChange={e => setEmail(e.target.value)} />
        <input className="border p-2 rounded" placeholder="password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
        <button className="bg-black text-white px-4 py-2 rounded disabled:opacity-50" onClick={doLogin} disabled={loading}>Iniciar sesión</button>
      </div>
    </div>
  )
}

