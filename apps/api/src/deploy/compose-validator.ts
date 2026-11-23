/** YAML parsing with bomb limits + the shared static Compose policy (P4.02, P4-T05). */
import {
  COMPOSE_MAX_BYTES,
  type ComposeValidation,
  validateComposeDocument,
} from '@ppanel/shared-contracts';
import { parseAllDocuments, visit } from 'yaml';

/** More aliases than this in one file is treated as an alias/merge-key bomb (never expanded). */
export const MAX_YAML_ALIASES = 50;
const MAX_ALIAS_EXPANSION = 100;

export function validateComposeYaml(
  text: string,
  opts: { environment?: 'production' | 'uat' | 'development' } = {},
): ComposeValidation {
  const fail = (rule: 'yaml_invalid' | 'yaml_alias_bomb', message: string): ComposeValidation => ({
    valid: false,
    violations: [{ service: null, rule, path: '$', message }],
    warnings: [],
    services: [],
  });
  if (Buffer.byteLength(text, 'utf8') > COMPOSE_MAX_BYTES)
    return fail('yaml_invalid', `Compose file larger than ${COMPOSE_MAX_BYTES} bytes`);
  const docs = parseAllDocuments(text, {
    uniqueKeys: true,
    merge: true,
    prettyErrors: false,
    strict: true,
  });
  if (!Array.isArray(docs)) return fail('yaml_invalid', 'Unparseable YAML');
  if (docs.length !== 1) return fail('yaml_invalid', 'Exactly one YAML document is required');
  const doc = docs[0]!;
  if (doc.errors.length) return fail('yaml_invalid', doc.errors[0]!.message.split('\n')[0]!);
  let aliases = 0;
  let mergeKeys = 0;
  visit(doc, {
    Alias() {
      aliases++;
    },
    Pair(_key, pair) {
      const k = (pair.key as { value?: unknown } | null)?.value;
      if (k === '<<') mergeKeys++;
    },
  });
  if (aliases > MAX_YAML_ALIASES || mergeKeys > MAX_YAML_ALIASES)
    return fail(
      'yaml_alias_bomb',
      `Too many YAML aliases/merge keys (${Math.max(aliases, mergeKeys)} > ${MAX_YAML_ALIASES})`,
    );
  let js: unknown;
  try {
    js = doc.toJS({ maxAliasCount: MAX_ALIAS_EXPANSION });
  } catch (e) {
    return fail('yaml_alias_bomb', (e as Error).message.split('\n')[0] ?? 'alias expansion limit');
  }
  return validateComposeDocument(js, opts);
}
