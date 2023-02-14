const {expect} = require('chai');
const ldap = require('./ldap');
const {describe, it} = require('mocha');

describe('LDAP Support @ldap', function() {
  it('should be able to get a list of LDAP service URLs @ldap.1', async function() {
    const urls = await ldap.lookupServiceUrls('direct.ccf.org');
    expect(urls).to.be.an('Array');
    expect(urls).not.to.be.empty;
    expect(urls[0]).to.match(/[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/);
  });

  it('Should be able to get the base DNs to search @ldap.2', async function() {
    this.timeout(10000);
    const baseDnList = await ldap.getBaseDnList('ldap://ldap.medicity.net:10389');
    expect(baseDnList).to.be.an('array');
    expect(baseDnList).not.to.be.empty;
    expect(baseDnList).to.include('dc=medicity,dc=net');
  });

  it('should be able to get the certificate for an LDAP served certificate @ldap.3', async function() {
    const certificate = await ldap.lookup(`direct.ccf.org`);
    console.log({certificate});
  });
});
