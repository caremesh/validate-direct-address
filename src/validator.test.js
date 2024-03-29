const Validator = require('./validator');

describe('Validator @Validator', function() {
  let validator;
  this.timeout(10000);

  before(async function() {
    validator = new Validator(undefined, 5000, 3);
  });

  it('Should reject a "fake" direct address @Validator.1', function(done) {
    expect(validator.assertValid('doc@example.com')).to.be.rejected.and.notify(done);
  });


  it('should reject a direct addresss that\'s in an invalid format @Validator.2', function(done) {
    expect(validator.assertValid('xample.com')).to.be.rejected.and.notify(done);
  });

  it('Should accept a "real" direct address with a domain certificate @Validator.3', function(done) {
    expect(validator.assertValid('patrick@direct.viacaremesh.com')).to.be.fulfilled.and.notify(done);
  });

  it('Should accept a "real" direct address with an individual certification @Validator.4', function(done) {
    expect(validator.assertValid('oncology@sunydmc.allscriptsdirect.net')).to.be.fulfilled.and.notify(done);
  });


  it('should detect if a cert wasn\'t signed by a HISP @Validator.5', function(done) {
    // Use mya ddress from our staging environment, which is not in the production trust bundle
    expect(validator.assertValid('patrick@caremeshstage.dmhisp.com')).to.be.rejected.and.notify(done);
  });


  it('should reject a direct addresss that\'s in an invalid format using isValid @Validator.6', async function() {
    expect(await validator.isValid('xample.com')).to.equal(false);
  });

  it('should acccept a direct addresss that\'s in a valid format using isValid @Validator.7', async function() {
    expect(await validator.isValid('patrick@direct.viacaremesh.com')).to.equal(true);
  });

  it('should reject a direct addresss that\'s in an invalid format @Validator.8', function(done) {
    expect(validator.assertValid('xample.com')).to.be.rejected.and.notify(done);
  });

  it('should properly handle a direct address where the lhs has embedded periods @Validator.9', async function() {
    expect(await validator.isValid('suncoastcommunityhealthcenters.inc@suncoastchc.eclinicaldirectplus.com'))
      .to.equal(true);
  });

  it('should properly handle a direct address managd with LDAP @Validator.10', async function() {
    expect(await validator.isValid('jcywinski50667@direct.ccf.org'))
      .to.equal(true);
  });

  it('should be able to lookup addresses at a single organization many times @Validate.11', async function() {
    this.timeout(5000);
    for (let i=0; i < 1000; i++) {
      await validator.isValid(`patrick@direct.viacaremesh.com`);
    }
  });

  describe('should be able to lookup addresses at a single organization many times @Validate.12', function() {
    this.timeout(10000);
    for (let i=0; i < 100; i++) {
      it(
        `Should validate name${i}@direct.viacaremesh.com @Validate.12.${i}`,
        () => validator.assertValid(`name${i}@direct.viacaremesh.com`),
      );
    }
  });
});
