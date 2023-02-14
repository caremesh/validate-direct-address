const {default: axios} = require('axios');
const asn1js = require('asn1js');
const pkijs = require('pkijs');
const _ = require('lodash');

module.exports = class TrustBundle {
  /**
   *
   * @param {string} trustBundleUrl the trust bundle url (optional)
   */
  constructor(trustBundleUrl = 'https://bundles.directtrust.org/bundles/accreditedCommunity.p7b') {
    this._trustBundleUrl = trustBundleUrl;
  }

  /**
   * fetch the trust bundle
   *
   * @param {boolean} force
   * @return {Object}
   */
  async fetch(force=false) {
    if (!this._trustBundle || force) {
      const result = await axios.get(this._trustBundleUrl);
      const b64 = result.data.replace(
          /(-----(BEGIN|END) PKCS7-----|[\n\r])/g,
          '');

      const der = Buffer.from(b64, 'base64');
      const ber = new Uint8Array(der).buffer;
      const asn1 = asn1js.fromBER(ber);
      const cmsContentSimpl = new pkijs.ContentInfo({schema: asn1.result});
      const cmsSignedSimpl = new pkijs.SignedData({
        schema: cmsContentSimpl.content,
      });

      this._trustBundle = cmsSignedSimpl;
    }

    return this._trustBundle;
  }

  /**
   * Search for a trusted HISP by issuer.
   *
   * @param {Buffer} cert the certificate to verify
   * @return {boolean}
   */
  async verifyCert(cert) {
    let crt;
    try {
      const der = Buffer.from(cert, 'base64');
      const ber = new Uint8Array(der).buffer;
      crt = pkijs.Certificate.fromBER(ber);
    } catch (error) {
      crt = pkijs.Certificate.fromBER(cert);
    }

    await this.fetch();

    // NOTE: this only confirms that the PUTATIVE issuer of the certificate is
    // in the DirectTrust trust bundle.  It does not guarantee that the cert
    // was actually issued by the specified CA.  This is sufficient for our
    // purposes.
    return !!_.find(this._trustBundle.certificates, (i) => i.subject.toString() == crt.issuer.toString());
  }
};

