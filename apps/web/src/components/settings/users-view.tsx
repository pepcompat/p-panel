'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ENVIRONMENTS,
  ROLE_KEYS,
  type RoleBinding,
  type RoleKey,
  type ScopeType,
} from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { usersApi } from '@/lib/api/endpoints';
import { isApiError, toApiError, type ApiError } from '@/lib/api/errors';
import type { UserRecord } from '@/lib/api/types';
import { qk } from '@/lib/queries';
import { relativeTime } from '@/lib/time';
import { envLabelKey } from '@/lib/servers';
import { useToast } from '@/components/providers/toast';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Dialog } from '@/components/ui/dialog';
import { Field, Input, Select } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';

const SCOPES: ScopeType[] = ['global', 'environment', 'project', 'server'];

function scopeText(b: RoleBinding, t: ReturnType<typeof useI18n>['t']) {
  return b.scopeType === 'global'
    ? t('scope.global')
    : `${t(`scope.${b.scopeType}`)}: ${b.scopeId ?? '—'}`;
}

function AddBindingDialog({ user, onClose }: { user: UserRecord; onClose: () => void }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const toast = useToast();
  const [roleKey, setRoleKey] = useState<RoleKey>('viewer');
  const [scopeType, setScopeType] = useState<ScopeType>('environment');
  const [scopeId, setScopeId] = useState<string>('development');
  const m = useMutation<unknown, ApiError>({
    mutationFn: () =>
      usersApi
        .addBinding(user.id, {
          roleKey,
          scopeType,
          scopeId: scopeType === 'global' ? undefined : scopeId.trim(),
        })
        .catch((e) => {
          throw toApiError(e);
        }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.users });
      toast(t('binding.added'), 'ok');
      onClose();
    },
  });
  const fe = m.error?.fieldErrors ?? {};
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      closeLabel={t('common.close')}
      title={t('binding.title', { user: user.displayName })}
      footer={
        <>
          <Button onClick={onClose}>{t('common.cancel')}</Button>
          <Button
            variant="primary"
            disabled={m.isPending || (scopeType !== 'global' && !scopeId.trim())}
            onClick={() => m.mutate()}
          >
            {m.isPending ? t('common.saving') : t('binding.add')}
          </Button>
        </>
      }
    >
      <Field label={t('binding.role')} error={fe.roleKey}>
        {(p) => (
          <Select {...p} value={roleKey} onChange={(e) => setRoleKey(e.target.value as RoleKey)}>
            {ROLE_KEYS.map((r) => (
              <option key={r} value={r}>
                {t(`role.${r}`)}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <Field label={t('binding.scope')} error={fe.scopeType}>
        {(p) => (
          <Select
            {...p}
            value={scopeType}
            onChange={(e) => {
              const v = e.target.value as ScopeType;
              setScopeType(v);
              setScopeId(v === 'environment' ? 'development' : '');
            }}
          >
            {SCOPES.map((s) => (
              <option key={s} value={s}>
                {t(`scope.${s}`)}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {scopeType === 'environment' && (
        <Field label={t('binding.scopeId')} error={fe.scopeId}>
          {(p) => (
            <Select {...p} value={scopeId} onChange={(e) => setScopeId(e.target.value)}>
              {ENVIRONMENTS.map((e) => (
                <option key={e} value={e}>
                  {t(envLabelKey(e))}
                </option>
              ))}
            </Select>
          )}
        </Field>
      )}
      {(scopeType === 'project' || scopeType === 'server') && (
        <Field label={t('binding.scopeId')} hint={t('binding.scopeIdHint')} error={fe.scopeId}>
          {(p) => (
            <Input
              {...p}
              value={scopeId}
              onChange={(e) => setScopeId(e.target.value)}
              className="font-mono"
            />
          )}
        </Field>
      )}
      {m.error && Object.keys(fe).length === 0 && <ErrorState error={m.error} />}
    </Dialog>
  );
}

function RemoveBindingDialog({
  user,
  binding,
  onClose,
}: {
  user: UserRecord;
  binding: RoleBinding;
  onClose: () => void;
}) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const toast = useToast();
  const m = useMutation<unknown, ApiError>({
    mutationFn: () =>
      usersApi.removeBinding(binding.id).catch((e) => {
        throw toApiError(e);
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.users });
      toast(t('binding.removed'), 'ok');
      onClose();
    },
  });
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      closeLabel={t('common.close')}
      title={t('binding.removeTitle')}
      description={t('binding.removeBody', {
        user: user.displayName,
        role: t(`role.${binding.roleKey}`),
        scope: scopeText(binding, t),
      })}
      footer={
        <>
          <Button onClick={onClose}>{t('common.cancel')}</Button>
          <Button variant="danger" disabled={m.isPending} onClick={() => m.mutate()}>
            {m.isPending ? t('common.saving') : t('common.confirm')}
          </Button>
        </>
      }
    >
      {m.error && <ErrorState error={m.error} />}
    </Dialog>
  );
}

export function UsersView() {
  const { t } = useI18n();
  const { can } = useAuth();
  const allowed = can('users.manage');
  const q = useQuery({
    queryKey: qk.users,
    queryFn: () => usersApi.list({ limit: 100 }),
    enabled: allowed,
  });
  const [adding, setAdding] = useState<UserRecord | null>(null);
  const [removing, setRemoving] = useState<{ user: UserRecord; binding: RoleBinding } | null>(null);
  const now = Date.now();

  if (!allowed || (isApiError(q.error) && q.error.status === 403)) {
    return (
      <ForbiddenState
        perm="users.manage"
        requestId={isApiError(q.error) ? q.error.requestId : null}
      />
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="m-0 text-[13px] text-fg-muted">{t('users.subtitle')}</p>
      <Card className="overflow-x-auto">
        {q.isPending ? (
          <TableSkeleton label={t('common.loading')} />
        ) : q.isError ? (
          <div className="p-4">
            <ErrorState error={q.error} onRetry={() => void q.refetch()} />
          </div>
        ) : q.data.items.length === 0 ? (
          <div className="p-4">
            <EmptyState title={t('users.empty')} />
          </div>
        ) : (
          <table className="w-full min-w-[760px] border-collapse text-[13px]">
            <thead>
              <tr className="bg-surface-2 text-left text-[12px] text-fg-muted">
                <th scope="col" className="px-4 py-[9px] font-medium">
                  {t('users.col.user')}
                </th>
                <th scope="col" className="px-2 py-[9px] font-medium">
                  {t('users.col.bindings')}
                </th>
                <th scope="col" className="px-2 py-[9px] font-medium">
                  {t('users.col.mfa')}
                </th>
                <th scope="col" className="px-2 py-[9px] font-medium">
                  {t('users.col.lastLogin')}
                </th>
                <th scope="col" className="px-4 py-[9px] font-medium">
                  <span className="sr-only">{t('users.addBinding')}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {q.data.items.map((u) => (
                <tr key={u.id} className="border-t border-line-subtle align-top">
                  <td className="px-4 py-2.5">
                    <div className="font-medium">{u.displayName}</div>
                    <div className="font-mono text-[12px] text-fg-muted">{u.email}</div>
                  </td>
                  <td className="px-2 py-2.5">
                    {u.bindings === undefined ? (
                      <span className="text-[12px] text-fg-muted">
                        {t('users.bindingsUnknown')}
                      </span>
                    ) : (
                      <ul className="m-0 flex list-none flex-wrap gap-1.5 p-0">
                        {u.bindings.map((b) => (
                          <li
                            key={b.id}
                            className="inline-flex items-center gap-1 rounded border border-line-strong bg-surface py-px pr-0.5 pl-2 text-[12px]"
                          >
                            <b className="font-medium">{t(`role.${b.roleKey}`)}</b>
                            <span className="text-fg-muted">· {scopeText(b, t)}</span>
                            <GatedButton
                              variant="ghost"
                              size="xs"
                              perm="users.manage"
                              aria-label={t('binding.remove', {
                                role: t(`role.${b.roleKey}`),
                                scope: scopeText(b, t),
                              })}
                              onClick={() => setRemoving({ user: u, binding: b })}
                            >
                              ✕
                            </GatedButton>
                          </li>
                        ))}
                      </ul>
                    )}
                  </td>
                  <td
                    className={`px-2 py-2.5 text-[12.5px] ${u.mfaEnabled ? 'text-ok' : 'text-warn'}`}
                  >
                    {u.mfaEnabled ? t('users.mfaOn') : t('users.mfaOff')}
                  </td>
                  <td className="px-2 py-2.5 text-[12.5px]">
                    {relativeTime(u.lastLoginAt, t, now)}
                  </td>
                  <td className="px-4 py-2 text-right">
                    <GatedButton size="sm" perm="users.manage" onClick={() => setAdding(u)}>
                      {t('users.addBinding')}
                    </GatedButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <Notice tone="neutral" role="note">
        {t('users.policyNote')}
      </Notice>
      {adding && <AddBindingDialog user={adding} onClose={() => setAdding(null)} />}
      {removing && (
        <RemoveBindingDialog
          user={removing.user}
          binding={removing.binding}
          onClose={() => setRemoving(null)}
        />
      )}
    </div>
  );
}
