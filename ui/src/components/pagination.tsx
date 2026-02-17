"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";

export function Pagination({
  total,
  pageSize,
  currentPage,
}: {
  total: number;
  pageSize: number;
  currentPage: number;
}) {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  function pageUrl(page: number) {
    const params = new URLSearchParams(searchParams.toString());
    params.set("page", String(page));
    return `${pathname}?${params.toString()}`;
  }

  if (totalPages <= 1) return null;

  return (
    <div className="flex items-center justify-between mt-4 text-sm text-zinc-400">
      <span>
        Page {currentPage} of {totalPages} ({total} total)
      </span>
      <div className="flex gap-2">
        {currentPage > 1 && (
          <Link
            href={pageUrl(currentPage - 1)}
            className="px-3 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300"
          >
            Previous
          </Link>
        )}
        {currentPage < totalPages && (
          <Link
            href={pageUrl(currentPage + 1)}
            className="px-3 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300"
          >
            Next
          </Link>
        )}
      </div>
    </div>
  );
}
