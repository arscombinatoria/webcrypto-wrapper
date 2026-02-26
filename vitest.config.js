const { defineConfig } = require('vitest/config');

module.exports = defineConfig({
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./jest.setup.js'],
    include: ['__tests__/**/*.test.js'],
    coverage: {
      reporter: ['json-summary', 'text', 'lcov', 'clover']
    }
  }
});
