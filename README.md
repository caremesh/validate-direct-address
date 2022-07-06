# validate-direct-address

Validates a Direct Trust email address. To be clear, validation with this library 
guarantees that an email address is a DirectTrust address.  It does not guarantee 
that messages sent to that address will be delivered or that the receiving system
will process it correctly.

## USAGE

```
const {Validator} = require('validate-direct-address');

async main() {
  const validator = new Validator();

  await validator.isValid('nonexistent@nowhere.com'); // Returns 'false' because the domain certificate does not exist
  await validator.isValid('nonexistent@direct.viacaremesh.com'); // Returns 'true' because the domain certificate exists.
  await validator.assertValid('nonexistent@nowhere.com'); // Throws an error
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
