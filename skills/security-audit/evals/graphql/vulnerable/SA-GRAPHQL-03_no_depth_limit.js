const { ApolloServer } = require('@apollo/server');

// VULNERABLE: no depth or complexity limit — deeply nested queries can DoS the server
const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [],
});

module.exports = { server };
