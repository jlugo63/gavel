import { IntegrityHeader } from "@/components/integrity-header";
import { AdminNav } from "@/components/nav";

export const dynamic = "force-dynamic";

export default function AdminLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-zinc-950">
      <IntegrityHeader />
      <AdminNav />
      <main className="p-6">{children}</main>
    </div>
  );
}
