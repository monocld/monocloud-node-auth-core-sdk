/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest/presets/js-with-ts',
  testEnvironment: 'node',
  moduleFileExtensions: ['ts', 'js'],
  testPathIgnorePatterns: ['tests/oauth4webapi'],
  coveragePathIgnorePatterns: [
    'tests/test-helpers.ts',
    'src/openid-client/oauth4webapi.ts',
  ],
};
