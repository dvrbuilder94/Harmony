import { useEffect, useState } from 'react'
import { login, setToken, registerAccount, verifyEmail, resendVerification } from '../api'

export default function Account() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [name, setName] = useState('')
  const [mode, setMode] = useState<'login' | 'register' | 'verify'>('login')
  const [token, setTokenStr] = useState('')

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

  const doRegister = async () => {
    setLoading(true)
    try {
      await registerAccount({ email, password, name })
      alert('Registrado. Revisa tu correo para verificar la cuenta.')
      setMode('verify')
    } catch (e) {
      alert('Registro falló')
    } finally {
      setLoading(false)
    }
  }

  const doVerify = async () => {
    setLoading(true)
    try {
      await verifyEmail(token)
      alert('Email verificado. Ahora puedes iniciar sesión.')
      setMode('login')
    } catch {
      alert('No se pudo verificar. Revisa el token o reenvía el correo.')
    } finally {
      setLoading(false)
    }
  }

  const doResend = async () => {
    setLoading(true)
    try {
      await resendVerification(email)
      alert('Correo de verificación reenviado')
    } catch {
      alert('No se pudo reenviar')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Cuenta</h1>
      <div className="flex gap-2 mb-4">
        <button className={`px-3 py-1 rounded border ${mode==='login'?'bg-black text-white':'bg-white'}`} onClick={()=>setMode('login')}>Iniciar sesión</button>
        <button className={`px-3 py-1 rounded border ${mode==='register'?'bg-black text-white':'bg-white'}`} onClick={()=>setMode('register')}>Crear cuenta</button>
        <button className={`px-3 py-1 rounded border ${mode==='verify'?'bg-black text-white':'bg-white'}`} onClick={()=>setMode('verify')}>Verificar email</button>
      </div>
      {mode === 'login' && (
        <div className="grid gap-2 max-w-md">
          <input className="border p-2 rounded" placeholder="email" value={email} onChange={e => setEmail(e.target.value)} />
          <input className="border p-2 rounded" placeholder="password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
          <button className="bg-black text-white px-4 py-2 rounded disabled:opacity-50" onClick={doLogin} disabled={loading}>Iniciar sesión</button>
        </div>
      )}
      {mode === 'register' && (
        <div className="grid gap-2 max-w-md">
          <input className="border p-2 rounded" placeholder="nombre (opcional)" value={name} onChange={e => setName(e.target.value)} />
          <input className="border p-2 rounded" placeholder="email" value={email} onChange={e => setEmail(e.target.value)} />
          <input className="border p-2 rounded" placeholder="password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
          <button className="bg-black text-white px-4 py-2 rounded disabled:opacity-50" onClick={doRegister} disabled={loading}>Crear cuenta</button>
        </div>
      )}
      {mode === 'verify' && (
        <div className="grid gap-2 max-w-md">
          <input className="border p-2 rounded" placeholder="token de verificación" value={token} onChange={e => setTokenStr(e.target.value)} />
          <div className="flex gap-2">
            <button className="bg-black text-white px-4 py-2 rounded disabled:opacity-50" onClick={doVerify} disabled={loading}>Verificar</button>
            <button className="bg-gray-100 border px-4 py-2 rounded disabled:opacity-50" onClick={doResend} disabled={loading || !email}>Reenviar correo</button>
          </div>
          <p className="text-xs text-gray-600">Consejo: si abriste el enlace desde tu correo, copia el token de la URL `verify-email?token=...` y pégalo aquí.</p>
        </div>
      )}
    </div>
  )
}

