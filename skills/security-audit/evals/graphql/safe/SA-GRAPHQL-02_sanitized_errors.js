const { ApolloServer } = require('@apollo/server');

// SAFE: stacktraces suppressed and errors sanitized for clients
const server = new ApolloServer({
  typeDefs,
  resolvers,
  includeStacktraceInErrorResponses: false,
  formatError: (formattedError) => {
    return { message: 'Internal error' };
  },
});

module.exports = { server };
