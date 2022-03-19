# KMS for PGP/GPG

This tool allows you to use [AWS KMS][aws-kms] asymmetric keys as if they were
PGP/GPG keys.

This can be useful if you have CI/CD pipelines signing code or artifacts and
you don't wish to do all the hassle of proper cryptographic key management.

## How to use?

Download the latest release from the Github Releases page. Since this is a Java
project you can get the Jar, distribution Zip (which you can conveniently
install on any OS) or a GraalVM native-image build for a fat binary that only
depends on the OS and architecture (no Java needed).

`kmspgp` only runs when the proper AWS credentials are set. It uses the AWS SDK
defaults which obey environment variables, profile files and/or instance
metadata credentials.

You should have already created an asymmetric key for signing/verification
only in KMS, and have the proper access to the key (`DescribeKey`,
`GetPublicKey` must be allowed). To list keys additionally the `ListKeys`
action should be allowed.

### Listing keys

You can list all usable keys with the `list` subcommand.

### Exporting a key

Exporting a key in the PGP/GPG format so that it can be shared publicly is done
using the `export` subcommand. You must pass the `--user-name`, `--user-email`
options wich govern the PGP/GPG user ID (`NAME <EMAIL> (COMMENT)` format).

Exporting requires the `Sign` action to be allowed, since it performs a signing
operation.

Usually you do this once, and then share the exported file.

### Signing data

You can sign data by using the `sign` subcommand. It reads from `STDIN` and
then signs the data using the provided key.

### GPG fallback mode for Git signing

You can use `kmspgp` in GPG fallback mode to sign Git commits. In your Git
project specify the following configuration:

```
git config --local gpg.program <PATH-TO-KMSPGP>
git config --local user.signingkey <KMS-KEY-ID>
git config --local commit.gpgsign true
git config --local tag.forceSignAnnotated true
```

Whenever you call `git commit` you would need AWS credentials setup so that
signing can take place.

## License

This software is Copyright &copy; Stojan Dimitrovski 2022.

Licensed under the MIT License. You can get a copy of it in the `LICENSE` file.

This distribution includes the excellent [Bouncy Castle library for Java][bc]
which is also licensed under the MIT license.

Additionally, some dependencies may be licensed under the Apache 2.0 license.

[aws-kms]: https://docs.aws.amazon.com/kms/latest/developerguide/overview.html
[bc]: https://www.bouncycastle.org/java.html
