# Third-party notices

## Known AWS account IDs

`src/data/known-aws-accounts.json` is converted from [fwdcloudsec/known_aws_accounts](https://github.com/fwdcloudsec/known_aws_accounts)
(commit `226d4f2`, 10 Nov 2026): the vendor names and AWS account IDs of `accounts.yaml`, reshaped as `{ account ID: vendor name }`.
It is used to name outside AWS accounts on the Trust map. Licensed under the Apache License 2.0; the licence text is in
`src/data/known-aws-accounts.LICENSE`. To update it, convert the newest `accounts.yaml` the same way.
