# KMS for PGP/GPG

This tool allows you to use [AWS KMS][aws-kms] asymmetric keys as if they were
PGP/GPG keys.

This can be useful if you have CI/CD pipelines signing code or artifacts and
you don't wish to do all the hassle of proper cryptographic key management.

## License

This software is Copyright &copy; Stojan Dimitrovski 2022.

Licensed under the MIT License. You can get a copy of it in the `LICENSE` file.

This distribution includes the excellent [Bouncy Castle library for Java][bc]
which is also licensed under the MIT license.

Additionally, some dependencies may be licensed under the Apache 2.0 license.

[aws-kms]: https://docs.aws.amazon.com/kms/latest/developerguide/overview.html
[bc]: https://www.bouncycastle.org/java.html
