import Link from 'next/link';

export default function NotFound() {
  return (
    <div className="grid min-h-screen place-items-center p-6">
      <div className="flex max-w-sm flex-col gap-2 rounded-[10px] border border-line bg-surface p-7">
        <h1 className="m-0 text-[20px] font-semibold">404</h1>
        <p className="m-0 text-[13.5px] text-fg-muted">This page does not exist.</p>
        <Link href="/overview">← pPanel</Link>
      </div>
    </div>
  );
}
