'use client';

import { useMutation, useQueryClient } from '@tanstack/react-query';
import type { Server } from '@ppanel/shared-contracts';
import { serversApi } from '@/lib/api/endpoints';
import type { ServerPatch } from '@/lib/api/types';
import { qk } from '@/lib/queries';
import type { ApiError } from '@/lib/api/errors';

/** PATCH /servers/:id with If-Match: <version>. A 409 VERSION_CONFLICT is surfaced, never retried blindly. */
export function usePatchServer(server: Server) {
  const qc = useQueryClient();
  return useMutation<Server, ApiError, ServerPatch>({
    mutationFn: (body) => serversApi.patch(server.id, body, server.version),
    onSuccess: (updated) => {
      qc.setQueryData(qk.server(server.id), updated);
      void qc.invalidateQueries({ queryKey: qk.servers, exact: true });
    },
  });
}
