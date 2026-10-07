const { ApolloServer } = require('@apollo/server');

// SAFE: HTTP query batching disabled
const server = new ApolloServer({
  typeDefs,
  resolvers,
  allowBatchedHttpRequests: false,
});

module.exports = { server };
