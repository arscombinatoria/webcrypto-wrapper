module.exports = {
  testEnvironment: 'jsdom',
  setupFilesAfterEnv: ['./jest.setup.js'],
  roots: ['<rootDir>/__tests__'],
  coverageReporters: ['json-summary', 'text', 'lcov', 'clover']
};
