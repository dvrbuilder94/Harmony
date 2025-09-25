import { Link, NavLink } from 'react-router-dom'
import { ReactNode } from 'react'

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen grid grid-cols-[240px_1fr]">
      <aside className="border-r bg-gray-50 p-4">
        <div className="font-bold text-lg mb-4">SalesHarmony</div>
        <nav className="flex flex-col gap-2 text-sm">
          <NavLink to="/" end className={({ isActive }) => isActive ? 'font-semibold' : ''}>Dashboard</NavLink>
          <NavLink to="/orders" className={({ isActive }) => isActive ? 'font-semibold' : ''}>Órdenes</NavLink>
          <NavLink to="/sync" className={({ isActive }) => isActive ? 'font-semibold' : ''}>Sincronización</NavLink>
          <NavLink to="/settings" className={({ isActive }) => isActive ? 'font-semibold' : ''}>Configuración</NavLink>
        </nav>
        <div className="mt-6 text-xs text-gray-500">
          <Link to="/" className="hover:underline">Inicio</Link>
        </div>
      </aside>
      <main className="p-6">
        {children}
      </main>
    </div>
  )
}

