const { ApolloServer } = require('@apollo/server');

// VULNERABLE: introspection hardcoded on — leaks the entire schema in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true,
});

module.exports = { server };
