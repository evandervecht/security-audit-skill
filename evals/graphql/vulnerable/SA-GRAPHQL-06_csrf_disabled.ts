import { ApolloServer } from '@apollo/server';

// VULNERABLE: CSRF prevention turned off — simple requests / GET mutations accepted
const server = new ApolloServer({
  typeDefs,
  resolvers,
  csrfPrevention: false,
});

export { server };
