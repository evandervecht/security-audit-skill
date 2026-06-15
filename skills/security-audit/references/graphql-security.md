# GraphQL Security Reference

## Overview

GraphQL exposes a single, flexible endpoint that can serve arbitrary query shapes. This
flexibility shifts the security model away from per-route REST controls and toward
schema-level, query-analysis, and resolver-level defenses. A single misconfigured
GraphQL server can leak its entire schema, allow denial-of-service via deeply nested
queries, or bypass per-request rate limiting through batching. This reference covers
detection patterns, vulnerable and secure examples (Apollo Server / graphql-js and SDL
schemas), and prevention strategies. It pairs with **[api-security.md](api-security.md)**,
which covers the OWASP API Top 10 and the broader GraphQL-specific section.

---

## GraphQL Threat Categories

### Introspection Enabled in Production

GraphQL introspection lets clients query the schema itself (`__schema`, `__type`),
revealing every type, field, mutation, and argument. This is invaluable in development
but hands attackers a complete map of the API surface in production.

#### Detection Patterns

- `introspection: true` hardcoded in an Apollo Server / Yoga configuration
- Introspection not gated behind an environment check
- `__schema`/`__type` queries answered in production responses

```js
// VULNERABLE: Introspection always enabled
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true,
});
```

```js
// SECURE: Introspection only in non-production environments
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
});
```

### Verbose Errors / Stacktrace Leakage

Debug modes and stacktrace inclusion expose internal file paths, library versions, and
SQL queries in error responses. Field-suggestion messages (“Did you mean …?”) leak
schema details even when introspection is disabled.

#### Detection Patterns

- `debug: true` or `includeStacktraceInErrorResponses: true`
- No custom `formatError` that strips internal detail in production
- Field suggestions left enabled

```js
// VULNERABLE: Stacktraces returned to clients
const server = new ApolloServer({
  typeDefs,
  resolvers,
  debug: true,
});
```

```js
// SECURE: Suppress stacktraces and sanitize errors in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  includeStacktraceInErrorResponses: false,
  formatError: (formattedError) => {
    if (process.env.NODE_ENV === 'production') {
      return { message: 'Internal error' };
    }
    return formattedError;
  },
});
```

### Missing Query Depth / Complexity Limits

Without depth and complexity analysis, a single deeply nested or wide query can cause
exponential database load and denial of service.

#### Detection Patterns

- Empty `validationRules: []`
- No `graphql-depth-limit`, `graphql-validation-complexity`, or `graphql-cost-analysis`
  rule registered

```js
// VULNERABLE: No depth or complexity limit
const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [],
});
```

```js
// SECURE: Enforce depth and cost limits
const depthLimit = require('graphql-depth-limit');
const { createComplexityLimitRule } = require('graphql-validation-complexity');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [depthLimit(7), createComplexityLimitRule(1000)],
});
```

### Missing Field-Level Authorization

GraphQL authorization should be enforced per field, not just per endpoint. Sensitive
fields (PII, credentials, secrets) returned without an `@auth`/`@hasRole` directive or
resolver-level check expose data to any caller who can reach the schema.

#### Detection Patterns

- Sensitive fields (`ssn`, `password`, `token`, `secret`, `apiKey`, `creditCard`)
  declared without an authorization directive
- Resolvers that return privileged fields without checking `context.user`

```graphql
# VULNERABLE: Sensitive fields exposed with no authorization
type User {
  id: ID!
  email: String!
  ssn: String!
  passwordHash: String!
}
```

```graphql
# SECURE: Field-level @auth directives gate sensitive data
type User {
  id: ID!
  email: String! @auth(requires: USER)
  ssn: String! @auth(requires: ADMIN)
  passwordHash: String! @auth(requires: ADMIN)
}
```

### Query Batching Abuse

GraphQL supports sending multiple operations in a single HTTP request. Attackers abuse
batching to brute-force credentials or coupons in one request, bypassing per-request
rate limiting.

#### Detection Patterns

- `allowBatchedHttpRequests: true` without a batch-size limit
- No per-operation cost accounting

```js
// VULNERABLE: Unbounded batching enables rate-limit bypass
const server = new ApolloServer({
  typeDefs,
  resolvers,
  allowBatchedHttpRequests: true,
});
```

```js
// SECURE: Disable batching (or cap batch size at the transport layer)
const server = new ApolloServer({
  typeDefs,
  resolvers,
  allowBatchedHttpRequests: false,
});
```

### CSRF via GET-Allowed Mutations

If the server accepts mutations over GET or simple `Content-Type` requests, a malicious
page can trigger state changes using the victim's cookies. Apollo's `csrfPrevention`
requires a preflight-triggering header before executing operations.

#### Detection Patterns

- `csrfPrevention: false`
- Mutations reachable via `GET` requests

```ts
// VULNERABLE: CSRF prevention disabled
const server = new ApolloServer({
  typeDefs,
  resolvers,
  csrfPrevention: false,
});
```

```ts
// SECURE: CSRF prevention enabled (requires a non-simple header)
const server = new ApolloServer({
  typeDefs,
  resolvers,
  csrfPrevention: true,
});
```

### Unbounded List / Pagination

List-returning fields without pagination arguments let clients request the entire
dataset, causing memory exhaustion and slow queries.

#### Detection Patterns

- Fields returning `[Type!]!` with no `first`/`last`/`limit`/`after`/`offset` argument
- Missing Relay-style connection types

```graphql
# VULNERABLE: Unbounded list fields
type Query {
  allUsers: [User!]!
  searchPosts(term: String!): [Post!]!
}
```

```graphql
# SECURE: Cursor / limit pagination on every list field
type Query {
  allUsers(first: Int!, after: String): UserConnection!
  searchPosts(term: String!, first: Int = 20, after: String): PostConnection!
}
```

### N+1 Query DoS

Resolvers that load related entities individually per parent create N+1 query problems.
Use the DataLoader pattern to batch and cache loads within a request. See the GraphQL
section of **[api-security.md](api-security.md)** for a worked DataLoader example.

---

## Prevention Checklist

### Schema and Authorization

- [ ] Apply field-level authorization (`@auth`/`@hasRole` directives or resolver checks) to every sensitive field
- [ ] Never expose credential, secret, or PII fields without an explicit authorization gate
- [ ] Add pagination arguments (`first`/`last`/`limit`/cursor) to every list-returning field
- [ ] Use Relay-style connection types instead of raw `[Type!]!` lists for collections

### Query Analysis

- [ ] Enforce a maximum query depth (e.g. 7) via a validation rule
- [ ] Enforce a maximum query complexity / cost score
- [ ] Apply per-field cost weighting for expensive resolvers
- [ ] Use the DataLoader pattern to batch resolve relations and prevent N+1 DoS

### Server Configuration

- [ ] Disable introspection in production (gate behind an environment check)
- [ ] Set `debug`/`includeStacktraceInErrorResponses` to false in production
- [ ] Provide a custom `formatError` that strips internal details and field suggestions in production
- [ ] Disable or strictly cap HTTP query batching (`allowBatchedHttpRequests`)
- [ ] Keep `csrfPrevention` enabled to block GET-based mutations and CSRF
- [ ] Apply per-user and per-IP rate limiting in front of the GraphQL endpoint
