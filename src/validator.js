/* eslint-disable new-cap */
const Promise = require('bluebird');
const debug = require('debug')('validate-direct-address');
const dns = require('native-node-dns');
const nodeDns = require('dns');
const _ = require('lodash');
const ldap = require('./ldap');
const LRU = require('lru-cache');

const TrustBundle = require('./trust-bundle');

const emailRegex = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i;
module.exports = class Validator {
  /**
   *
   * @param {string} trustBundleUrl override the default trust bundle URL
   * @param {number} [timeout] DNS timeout
   * @param {number} [retries] how many times to retry
   * @param {address} [address] the DNS server address to use
   * @param {number} [maxCacheEntries] the maximum cache size in entries
   */
  constructor(trustBundleUrl, timeout = 30000, retries = 3, address = null, maxCacheEntries = 10000) {
    this.trustBundle = new TrustBundle(trustBundleUrl);
    this.timeout = timeout;
    this.retries = retries;
    if (address) {
      this.address = address;
    } else {
      this.address = nodeDns.getServers()[0];
    }
    debug(`DNS server address is ${this.address}`);
    this.cache = new LRU({
      max: maxCacheEntries,
      updateAgeOnGet: true,
    });
  }

  /**
   * Return true or false (but don't throw) to indicate
   * whether a direct address is valid.
   * @param {string} address a direct address to validate
   * @return {Promise<boolean>}
   */
  async isValid(address) {
    try {
      await this.assertValid(address);
      return true;
    } catch (error) {
      console.error(error);
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
    for (let i = 0; i < this.retries; i++) {
      try {
        debug(`try ${i} for ${lhs}.${rhs}`);
        results = await this._lookup(`${lhs}.${rhs}`);
        if (results[0]) break;
      } catch (error) {
        try {
          debug(`try ${i} for ${rhs}`);
          results = await this._lookup(rhs);
          if (_.isArray(results) && results[0]) break;
        } catch (error) {
          debug(error);
          throw new Error(`Could not find matching CERT record for ${address}: ${error.message}`);
        }
      }
    }

    if (results[0] == null) {
      throw new Error(`Got no results for ${address}`);
    }

    if (!await this.trustBundle.verifyCert(results[0].toString('base64'))) {
      throw new Error(`Certificate for ${address} was not signed by a HISP!`);
    }

    return true;
  }

  /**
   * Lookup a cert record for the specified domain
   * @param {string} binding the domain name to lookup
   * @return {Promise<string>}
   */
  async _lookup(binding) {
    const self = this;

    if (this.cache.has(binding)) {
      return this.cache.get(binding);
    }

    const address = this.address;
    return await new Promise((resolve, reject) => {
      let results;
      const question = dns.Question({
        name: binding,
        type: 'CERT',
      });

      debug(`DNS Server is ${address}`);
      const req = dns.Request({
        question: question,
        server: {address, port: 53, type: 'tcp'},
        timeout: this.timeout,
      });

      req.on('timeout', () => {
        log.error(`Timeout trying to fetch information for ${binding}`);
        reject(new Error(`Timeout`));
      });

      req.on('message', function(err, response) {
        if (_.get(response, 'answer.length', 0) == 0) {
          return null;
        }
        results = _.compact(
          _.map(response.answer, (i) => {
            if (_.has(i, 'data.buffer')) {
              return i.data.buffer.slice(5);
            }
          }),
        );
      });

      req.on('error', function(error) {
        log.error(`Caught error trying to validate ${binding}: ${_.get(error, 'message', 'undefined')}`);
        reject(error);
      });

      req.on('end', async function() {
        if (_.isEmpty(results)) {
          let ldapCert = await ldap.lookup(binding);
          if (ldapCert) {
            ldapCert = Buffer.from(ldapCert, 'base64');
            debug({ldapCert: ldapCert.toString()});
            self.cache.set(binding, [ldapCert]);
            resolve([ldapCert]);
          }
        }

        self.cache.set(binding, results);
        resolve(results);
      });

      req.send();
    });
  }
};
