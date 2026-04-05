"use client";

import { useState } from "react";

export function ExpandableRow({
  cells,
  expandedContent,
}: {
  cells: React.ReactNode[];
  expandedContent: React.ReactNode;
}) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <tr
        onClick={() => setOpen(!open)}
        className="border-b border-zinc-800 hover:bg-zinc-900 cursor-pointer transition-colors"
      >
        {cells.map((cell, i) => (
          <td key={i} className="px-3 py-2 text-sm">
            {cell}
          </td>
        ))}
        <td className="px-3 py-2 text-sm text-zinc-600">
          {open ? "\u25B2" : "\u25BC"}
        </td>
      </tr>
      {open && (
        <tr className="border-b border-zinc-800 bg-zinc-900/50">
          <td colSpan={cells.length + 1} className="px-4 py-3">
            {expandedContent}
          </td>
        </tr>
      )}
    </>
  );
}
