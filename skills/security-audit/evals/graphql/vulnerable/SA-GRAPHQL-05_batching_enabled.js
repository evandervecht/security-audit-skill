const { ApolloServer } = require('@apollo/server');

// VULNERABLE: unbounded batching lets attackers send many operations per request
const server = new ApolloServer({
  typeDefs,
  resolvers,
  allowBatchedHttpRequests: true,
});

module.exports = { server };
