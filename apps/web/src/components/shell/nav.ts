import type { MessageKey } from '@/i18n/en';

export interface NavItem {
  id: string;
  href: string;
  /** Prefix that marks the item active (defaults to href). */
  match?: string;
  label: MessageKey;
  section: MessageKey;
  /** true = renders design layout with mock data (backend PROPOSED). */
  preview?: boolean;
}

/** Mirrors the design prototype's NAV array (18 items, 4 sections) and ROUTES map. */
export const NAV: NavItem[] = [
  { id: 'overview', href: '/overview', label: 'nav.overview', section: 'nav.section.operate' },
  { id: 'servers', href: '/servers', label: 'nav.servers', section: 'nav.section.operate' },
  {
    id: 'apps',
    href: '/applications',
    label: 'nav.applications',
    section: 'nav.section.operate',
  },
  {
    id: 'deploy',
    href: '/deployments',
    label: 'nav.deployments',
    section: 'nav.section.operate',
  },
  {
    id: 'approvals',
    href: '/approvals',
    label: 'nav.approvals',
    section: 'nav.section.operate',
  },
  {
    id: 'imports',
    href: '/imports',
    label: 'nav.imports',
    section: 'nav.section.operate',
  },
  {
    id: 'network',
    href: '/network',
    label: 'nav.network',
    section: 'nav.section.infrastructure',
  },
  {
    id: 'firewall',
    href: '/firewall',
    label: 'nav.firewall',
    section: 'nav.section.infrastructure',
    preview: true,
  },
  {
    id: 'ssh',
    href: '/ssh',
    label: 'nav.ssh',
    section: 'nav.section.infrastructure',
    preview: true,
  },
  {
    id: 'plugins',
    href: '/plugins',
    label: 'nav.plugins',
    section: 'nav.section.infrastructure',
    preview: true,
  },
  {
    id: 'runtimes',
    href: '/runtimes',
    label: 'nav.runtimes',
    section: 'nav.section.infrastructure',
    preview: true,
  },
  {
    id: 'databases',
    href: '/databases',
    label: 'nav.databases',
    section: 'nav.section.infrastructure',
    preview: true,
  },
  {
    id: 'monitoring',
    href: '/monitoring',
    label: 'nav.monitoring',
    section: 'nav.section.observe',
  },
  { id: 'logs', href: '/logs', label: 'nav.logs', section: 'nav.section.observe' },
  {
    id: 'backups',
    href: '/backups',
    label: 'nav.backups',
    section: 'nav.section.observe',
  },
  {
    id: 'alerts',
    href: '/alerts',
    label: 'nav.alerts',
    section: 'nav.section.observe',
  },
  {
    id: 'ai',
    href: '/ai-mcp',
    label: 'nav.aiMcp',
    section: 'nav.section.automation',
    preview: true,
  },
  {
    id: 'settings',
    href: '/settings/users',
    match: '/settings',
    label: 'nav.settings',
    section: 'nav.section.automation',
  },
];

export function isActive(item: NavItem, pathname: string) {
  const m = item.match ?? item.href;
  return pathname === m || pathname.startsWith(`${m}/`);
}
