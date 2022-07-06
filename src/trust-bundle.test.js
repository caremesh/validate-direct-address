const TrustBundle = require('./trust-bundle');

describe('TrustBundle', function() {
  let trustBundle;

  before(async function() {
    trustBundle = new TrustBundle();
  });

  it(`Should be able to get a trust bundle @TrustBundle.fetch`, function(done) {
    this.timeout(10000);
    expect(trustBundle.fetch()).to.be.fulfilled.and.notify(done);
  });
});
