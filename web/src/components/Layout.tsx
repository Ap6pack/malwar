// Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
import { useState, useEffect } from 'react'
import { Outlet, NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  Search,
  History,
  Fingerprint,
  Shield,
  Menu,
  X,
} from 'lucide-react'
import { cn } from '../lib/utils'
import { api } from '../lib/api'

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/scan', label: 'New Scan', icon: Search, end: false },
  { to: '/scans', label: 'Scan History', icon: History, end: false },
  { to: '/signatures', label: 'Signatures', icon: Fingerprint, end: false },
  { to: '/campaigns', label: 'Campaigns', icon: Shield, end: false },
]

export function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [healthOk, setHealthOk] = useState<boolean | null>(null)

  useEffect(() => {
    api.health()
      .then(() => setHealthOk(true))
      .catch(() => setHealthOk(false))
  }, [])

  return (
    <div className="flex h-screen overflow-hidden bg-bg">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r border-border bg-bg-card transition-transform duration-200 lg:static lg:translate-x-0',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        {/* Branding */}
        <div className="flex items-center gap-3 border-b border-border px-5 py-5">
          <div className="flex items-center gap-2">
            <Shield className="h-7 w-7 text-accent" />
            <span className="text-xl font-bold tracking-wide text-text">MALWAR</span>
          </div>
          <span className="rounded-full bg-accent/15 px-2 py-0.5 text-xs font-medium text-accent">
            v1
          </span>
          {/* Close button for mobile */}
          <button
            className="ml-auto text-text-muted hover:text-text lg:hidden"
            onClick={() => setSidebarOpen(false)}
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 space-y-1 px-3 py-4">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-accent/10 text-accent'
                    : 'text-text-muted hover:bg-bg-hover hover:text-text'
                )
              }
            >
              <item.icon className="h-5 w-5 shrink-0" />
              {item.label}
            </NavLink>
          ))}
        </nav>

        {/* Health indicator */}
        <div className="border-t border-border px-5 py-4">
          <div className="flex items-center gap-2 text-xs text-text-muted">
            <span
              className={cn(
                'h-2 w-2 rounded-full',
                healthOk === true && 'bg-severity-low',
                healthOk === false && 'bg-severity-critical',
                healthOk === null && 'bg-text-muted animate-pulse'
              )}
            />
            <span>
              {healthOk === true && 'Backend connected'}
              {healthOk === false && 'Backend unreachable'}
              {healthOk === null && 'Checking...'}
            </span>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Mobile header */}
        <header className="flex items-center border-b border-border bg-bg-card px-4 py-3 lg:hidden">
          <button
            className="text-text-muted hover:text-text"
            onClick={() => setSidebarOpen(true)}
          >
            <Menu className="h-6 w-6" />
          </button>
          <div className="ml-3 flex items-center gap-2">
            <Shield className="h-5 w-5 text-accent" />
            <span className="font-bold text-text">MALWAR</span>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
