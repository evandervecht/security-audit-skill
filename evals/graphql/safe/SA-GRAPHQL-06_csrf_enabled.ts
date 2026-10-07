import { ApolloServer } from '@apollo/server';

// SAFE: CSRF prevention enabled — requires a preflight-triggering header
const server = new ApolloServer({
  typeDefs,
  resolvers,
  csrfPrevention: true,
});

export { server };
