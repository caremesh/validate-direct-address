'use strict';

module.exports = {
  diff: true,
  extension: ['js'],
  package: './package.json',
  file: [
    '.mocha-init.js',
  ],
  spec: [
    'src/**/*.test.js',
  ],
  reporter: 'spec',
  slow: 75,
  timeout: 2000,
  ui: 'mocha-cakes-2',
  'watch-files': ['src/**/*.js'],
  'watch-ignore': ['lib/vendor']
};