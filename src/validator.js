/* eslint-disable new-cap */
const Promise = require('bluebird');
const dns = require('native-node-dns');

const TrustBundle = require('./trust-bundle');

const emailRegex = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i;


module.exports = class Validator {
  /**
   *
   * @param {string} trustBundleUrl override the default trust bundle URL
   */
  constructor(trustBundleUrl) {
    this.trustBundle = new TrustBundle(trustBundleUrl);
  }

  /**
   * Return true or false (but don't throw) to indicate
   * whether a direct address is valid.
   * @param {string} address a direct address to validate
   * @return {Promise<boolean>}
   */
  async isValid(address) {
    try {
      return await this.assertValid(address);
    } catch (error) {
      return false;
    }
  }

  /**
   * @param {string} address a direct address to validate
   * @return {Promise<boolean>}
   */
  async assertValid(address) {
    if (!emailRegex.test(address)) {
      throw new Error(`Invalid direct address format: ${address}`);
    }

    // First lookup `user.domain.com`, then if that fails try `domain.com`
    const [lhs, rhs] = address.split(/@/);
    let results;
    try {
      results = await this._lookup(`${lhs}.${rhs}`);
    } catch (error) {
      try {
        results = await this._lookup(rhs);
      } catch (error) {
        throw new Error(`Could not find matching CERT record for ${address}: ${error.message}`);
      }
    }

    if (!await this.trustBundle.verifyCert(results[0].toString('base64'))) {
      throw new Error(`Certificate for ${address} was not signed by a HISP!`);
    }
    return true;
  }

  /**
   * Lookup a cert record for the specified domain
   * @param {string} domain the domain name to lookup
   * @return {Promise<string>}
   */
  _lookup(domain) {
    return new Promise((resolve, reject) => {
      let results;
      const question = dns.Question({
        name: domain,
        type: 'CERT',
      });

      const req = dns.Request({
        question: question,
        server: {address: '8.8.8.8', port: 53, type: 'tcp',
        },
        timeout: 1000,
      });

      req.on('timeout', () => {
        reject(new Error(`Timeout`));
      });

      req.on('message', function(err, response) {
        if (_.get(response, 'answer.length', 0) == 0) {
          return reject(new Error(`No such domain: ${domain}`));
        }
        results = _.map(response.answer, (i) => {
          return i.data.buffer.slice(5);
        });
      });

      req.on('end', function() {
        resolve(results);
      });

      req.send();
    });
  }
};
