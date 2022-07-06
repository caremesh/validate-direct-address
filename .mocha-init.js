const chai = require('chai');
const path = require('path');

global.Promise = require('bluebird');
global.chai = require('chai');
global._ = require('lodash');

global.expect = chai.expect;
chai.use(require('chai-string'));
chai.use(require('chai-as-promised'));

before(async function () {
  this.timeout(30000);
});


