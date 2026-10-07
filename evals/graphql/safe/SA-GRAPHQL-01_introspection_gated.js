const { ApolloServer } = require('@apollo/server');

// SAFE: introspection only enabled outside production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
});

module.exports = { server };
