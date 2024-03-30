/** @type {import('ts-jest').JestConfigWithTsJest} */
export default {
  preset: 'ts-jest/presets/js-with-ts',
  testEnvironment: 'node',
  moduleFileExtensions: ['ts', 'js'],
  testPathIgnorePatterns: ['tests/oauth4webapi'],
  coveragePathIgnorePatterns: [
    'node_modules',
    'tests/test-mocks.ts',
    'src/openid-client/oauth4webapi.ts',
  ],
};
