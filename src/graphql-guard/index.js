import { parse, Kind } from 'graphql';
import { bufferRequestBody } from '../proxy/body-buffer.js';

/**
 * FR3: detect/block excessive-depth, excessive-complexity, batching abuse,
 * and introspection abuse on GraphQL endpoints, in front of DVGA.
 *
 * This is deliberately schema-agnostic - ArmourAPI is a reverse proxy and
 * has no execution-time access to the upstream's GraphQLSchema, so depth and
 * complexity are computed by walking the parsed query AST directly (field
 * count + nesting depth), rather than via graphql-depth-limit/graphql-query-
 * complexity, which are validation rules that require `validate(schema, ...)`.
 * Fragment spreads are resolved against fragments defined in the same
 * document so `...Frag` can't be used to dodge the depth count.
 */

const DEFAULT_MAX_DEPTH = 5; // per doc Section 5.1: "Cap query depth to a max of 5 levels"
const DEFAULT_MAX_COMPLEXITY = 200; // total field selections across the query
const DEFAULT_MAX_BATCH_SIZE = 5; // requests sending an array of operations in one call

function analyzeQuery(query, { maxDepth, maxComplexity, allowIntrospection }) {
  let document;
  try {
    document = parse(query);
  } catch {
    return { allow: false, category: 'graphql-malformed', reason: 'Query failed to parse' };
  }

  const fragmentsByName = new Map();
  for (const def of document.definitions) {
    if (def.kind === Kind.FRAGMENT_DEFINITION) fragmentsByName.set(def.name.value, def);
  }

  let maxDepthSeen = 0;
  let fieldCount = 0;
  let introspectionUsed = false;
  const seenFragments = new Set(); // guards against fragment-cycle DoS

  function walkSelectionSet(selectionSet, depth) {
    maxDepthSeen = Math.max(maxDepthSeen, depth);
    if (maxDepthSeen > maxDepth || fieldCount > maxComplexity) return; // short-circuit, no need to keep walking

    for (const selection of selectionSet.selections) {
      if (selection.kind === Kind.FIELD) {
        fieldCount++;
        if (selection.name.value === '__schema' || selection.name.value === '__type') {
          introspectionUsed = true;
        }
        if (selection.selectionSet) walkSelectionSet(selection.selectionSet, depth + 1);
      } else if (selection.kind === Kind.INLINE_FRAGMENT) {
        if (selection.selectionSet) walkSelectionSet(selection.selectionSet, depth);
      } else if (selection.kind === Kind.FRAGMENT_SPREAD) {
        const name = selection.name.value;
        const frag = fragmentsByName.get(name);
        if (frag && !seenFragments.has(name)) {
          seenFragments.add(name);
          walkSelectionSet(frag.selectionSet, depth);
          seenFragments.delete(name);
        }
      }
      if (maxDepthSeen > maxDepth || fieldCount > maxComplexity) return;
    }
  }

  for (const def of document.definitions) {
    if (def.kind === Kind.OPERATION_DEFINITION) walkSelectionSet(def.selectionSet, 1);
  }

  if (introspectionUsed && !allowIntrospection) {
    return { allow: false, category: 'graphql-introspection', reason: 'Introspection queries are disabled' };
  }
  if (maxDepthSeen > maxDepth) {
    return {
      allow: false,
      category: 'graphql-depth',
      reason: `Query depth ${maxDepthSeen} exceeds max ${maxDepth}`,
    };
  }
  if (fieldCount > maxComplexity) {
    return {
      allow: false,
      category: 'graphql-complexity',
      reason: `Query complexity ${fieldCount} exceeds max ${maxComplexity}`,
    };
  }
  return { allow: true };
}

function extractOperations(request, bodyBuffer) {
  if (request.method === 'GET') {
    const query = request.query?.query;
    if (!query) return [];
    let variables;
    if (typeof request.query?.variables === 'string') {
      try {
        variables = JSON.parse(request.query.variables);
      } catch {
        // leave undefined; malformed variables aren't this guard's concern
      }
    }
    return [{ query, variables }];
  }

  if (!bodyBuffer || bodyBuffer.length === 0) return [];
  let parsedBody;
  try {
    parsedBody = JSON.parse(bodyBuffer.toString('utf8'));
  } catch {
    return null; // signals "malformed JSON" to the caller
  }
  return Array.isArray(parsedBody) ? parsedBody : [parsedBody];
}

export function createGraphqlGuard(options = {}) {
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  const maxComplexity = options.maxComplexity ?? DEFAULT_MAX_COMPLEXITY;
  const maxBatchSize = options.maxBatchSize ?? DEFAULT_MAX_BATCH_SIZE;
  const allowIntrospection = options.allowIntrospection ?? false;

  return {
    name: 'graphql-guard',

    async scan(request) {
      const bodyBuffer = await bufferRequestBody(request);
      const operations = extractOperations(request, bodyBuffer);

      if (operations === null) {
        return { allow: false, category: 'graphql-malformed', reason: 'Request body is not valid JSON' };
      }
      if (operations.length === 0) {
        return { allow: true }; // nothing to inspect (e.g. GraphiQL asset requests)
      }
      if (operations.length > maxBatchSize) {
        return {
          allow: false,
          category: 'graphql-batching',
          reason: `Batch of ${operations.length} operations exceeds max ${maxBatchSize}`,
        };
      }

      for (const op of operations) {
        if (!op || typeof op.query !== 'string') {
          return { allow: false, category: 'graphql-malformed', reason: 'Operation missing a query string' };
        }
        const result = analyzeQuery(op.query, { maxDepth, maxComplexity, allowIntrospection });
        if (!result.allow) return result;
      }

      return { allow: true };
    },
  };
}
