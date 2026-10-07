const { ApolloServer } = require('@apollo/server');

// VULNERABLE: debug mode returns stacktraces and internal details to clients
const server = new ApolloServer({
  typeDefs,
  resolvers,
  debug: true,
});

module.exports = { server };
