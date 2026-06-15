const { ApolloServer } = require('@apollo/server');
const depthLimit = require('graphql-depth-limit');
const { createComplexityLimitRule } = require('graphql-validation-complexity');

// SAFE: depth and complexity limits enforced on every query
const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [depthLimit(7), createComplexityLimitRule(1000)],
});

module.exports = { server };
