const Validator = require('./validator');

describe('Validator @Validator', function() {
  let validator;

  before(async function() {
    this.timeout(10000);
    validator = new Validator();
  });

  it('Should reject a "fake" direct address @Validator.1', function(done) {
    expect(validator.assertValid('doc@example.com')).to.be.rejected.and.notify(done);
  });

  it('Should accept a "real" direct address with a domain certificate @Validator.2', function(done) {
    expect(validator.assertValid('patrick@direct.viacaremesh.com')).to.be.fulfilled.and.notify(done);
  });

  it('Should accept a "real" direct address with an individual certification @Validator.3', function(done) {
    expect(validator.assertValid('oncology@sunydmc.allscriptsdirect.net')).to.be.fulfilled.and.notify(done);
  });

  it('should reject an direct addresss that\'s in an invalid format @Validator.4', function(done) {
    expect(validator.assertValid('xample.com')).to.be.rejected.and.notify(done);
  });

  it('should detect if a cert wasn\'t signed by a HISP @Validator.5', function(done) {
    // Use mya ddress from our staging environment, which is not in the production trust bundle
    expect(validator.assertValid('patrick@caremeshstage.dmhisp.com')).to.be.rejected.and.notify(done);
  });
});
