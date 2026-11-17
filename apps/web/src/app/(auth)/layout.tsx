export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return <div className="grid min-h-screen place-items-center overflow-auto bg-bg p-6">{children}</div>;
}
