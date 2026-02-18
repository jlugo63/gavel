"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const links = [
  { href: "/admin/events", label: "Audit Events" },
  { href: "/admin/intents", label: "Inbound Intents" },
  { href: "/admin/policy", label: "Policy Decisions" },
];

export function AdminNav() {
  const pathname = usePathname();

  return (
    <nav className="border-b border-zinc-800 bg-zinc-950 px-6 py-3">
      <div className="flex items-center gap-8">
        <Link
          href="/admin/events"
          className="font-mono text-sm font-bold tracking-wider text-zinc-300"
        >
          GAVEL
        </Link>
        <div className="flex gap-1">
          {links.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className={`px-3 py-1.5 text-sm rounded transition-colors ${
                pathname === link.href
                  ? "bg-zinc-800 text-white"
                  : "text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900"
              }`}
            >
              {link.label}
            </Link>
          ))}
        </div>
      </div>
    </nav>
  );
}
