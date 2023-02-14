/* eslint-disable new-cap */
const Promise = require('bluebird');
const debug = require('debug')('validate-direct-address');
const dns = require('native-node-dns');
const nodeDns = require('dns');
const _ = require('lodash');
const ldap = require('ldapjs');


/* eslint-disable */
function _ldapSearch(url, base='', filter='', scope='sub', attributes=null) {
  client = ldap.createClient({
    url: [url],
  });


  return new Promise((resolve, reject) => {
    client.on('error', reject);

    client.bind('', '', (err) => {
      if (err) {
        reject(err);
      };

      client.search(
        base, 
        {
          scope,
          filter,
          attributes,
        }, (error, res) => {
          let results = [];
   
          if (error) {
            debug({
              location: `_ldapSearch#searchError`,
              message: error.message,
            });
   
            reject(error);
          }
   
          res.on('searchEntry', (entry) => {
            debug({
              location: `_ldapSearch#searcEntry`,
              object: entry.object
            });
            results.push(entry.object);
          });
   
          res.on('error', (error) => {
            debug({
              location: `_ldapSearch#error`,
              message: error.message,
            });
            reject(error);
          });
   
          res.on('end', (response) => {
            // debug({
            //   location: `_ldapSearch#end`,
            //   response,
            //   results,
            // });
   
            client.unbind(() => resolve(results));
          });
        });
      }); 
    });
}

/**
 * Attempt to find an ldap server for the specified
 * binding.
 *
 * @param {string} binding the domain name to lookup
 * @param {string} address the DNS server to use
 * @return {Promise<Array<string>>}
 */
function lookupServiceUrls(binding, address) {
  if (!address) {
    address = nodeDns.getServers()[0];
  }

  debug(`Attempting lookup for ${binding}@${address}`);
  return new Promise((resolve, reject) => {
    let results;
    const question = dns.Question({
      name: `_ldap._tcp.${binding}`,
      type: 'SRV',
    });

    debug(`DNS Server is ${address}`);
    const req = dns.Request({
      question: question,
      server: {address, port: 53, type: 'tcp'},
      timeout: this.timeout,
    });

    req.on('timeout', (err) => {
      debug(`Got timeout error: ${err.message}`);
      reject(new Error(`Timeout`));
    });

    req.on('message', function(err, response) {
      if (err) {
        debug({
          message: err.message,
          stack: err.stack,
        });
        reject(err);
      }

      if (_.get(response, 'answer.length', 0) == 0) {
        return null;
      }

      results = _.compact(
          _.map(response.answer, (i) => {
            if (_.has(i, 'target')) {
              return `ldap://${i.target}:${i.port}`;
            }
          }),
      );
    });

    req.on('error', function(error) {
      reject(error);
    });

    req.on('end', function() {
      resolve(results);
    });

    req.send();
  });
}

/**
   * Lookup a certificate for the specified direct certificate using LDAP binding
   * and return the base64 encoded certificate.
   *
   * @param {string} binding the domain name to lookup
   * @return {Promise<string>}
   */
async function lookup(binding) {
  const urls = await lookupServiceUrls(binding);
  if (_.isEmpty(urls)) {
    debug(`Couldn't find binding for ${binding}.  This probably means that the requested binding does not exist`);
    return undefined;
  }

  let results = await Promise.map(
    urls,
    async(url) => {
      let dnList = await getBaseDnList(url);
      debug({dnList});
      for (let dn of dnList) {
        let result = await _ldapSearch(url, dn, `mail=${binding}`, 'sub')
        for (let row of result) {
          let cert = _.get(row, 'userCertificate;binary', _.get(row, 'userCertificate'));
          if (cert) {
            return cert;
          }
        }
      }
    },
  );

  return _.first(results);
}

/**
 * Get base DNS for the requested URL
 *
 * @param {string} url
 * @return {Promise<string>}
 */
async function getBaseDnList(url) {
  try {
    let candidates = await _ldapSearch(url, '', 'objectclass=*', 'base', ['namingContexts']);
    let results = _.map(candidates, 'namingContexts');
    debug(results);
    return results;
  } catch(error) {
    log.error({
      message: error.message,
      stack: error.stack,
    });
    throw(error);
  }
}

module.exports = {
  lookupServiceUrls,
  lookup,
  getBaseDnList,
};
