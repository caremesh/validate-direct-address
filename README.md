# validate-direct-address

Validates a Direct Trust email address.  The main purpose in developing this library is to 
prevent users from entering email addresses in as direct addresses.

To be clear, validation with this library checks that an email address is a 
DirectTrust address.  It does not guarantee that messages sent to that 
address will be delivered or that the receiving system will process it 
correctly.  More importantly, while it confirms that the certificate 
**appears** to be signed by a CA in the trust bundle, it does not guarantee
it.  It's for validating input, not security.

It has not been tested (and probably won't work) in the browser environment.

## USAGE

```
const {Validator} = require('validate-direct-address');

async main() {
   // use the default trust bundle, 1000ms timeout, 2 retries.  All options are optional
  const validator = new Validator(undefined, 1000, 2);

  await validator.isValid('nonexistent@nowhere.com'); // Returns 'false' because the domain certificate does not exist
  await validator.isValid('nonexistent@direct.viacaremesh.com'); // Returns 'true' because the domain certificate exists.
  await validator.assertValid('nonexistent@nowhere.com'); // Throws an error.  Use this or isValid based on what fits your code
}
```

## TESTS

We strive for 100% test coverage.  To run them, run `yarn test` or `npm run test`.

## METHOD

Assuming a direct address of "jsmith@direct.hospital.org":

1. do a DNS lookup for a `cert` record for `jsmith.direct.hospital.org`.  (Note that 
   you must replace the '@' with a '.'.  If this succeeds, go to step 4.
2. do a DNS lookup for a `cert` record for `direct.hospital.org`.  (Not the removal 
   of the RHS of the address.)  If this succeds, go to step 4.
3. If you haven't yet gotten the certificate, exit.
4. Using node crypto tools, decode the content of the cert record.  You may need to 
   play around with it to get it to work, but it is in X.509 format.
5. The issuer "cn" of the certificate must be one of the organizations listed in the 
   directTrust trust bundle, which can be downloaded from 
   https://directtrust.org/trust-bundles/accredited-trust-bundle
