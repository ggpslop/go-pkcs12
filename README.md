# package pkcs12

[![Documentation](https://pkg.go.dev/badge/github.com/ggpslop/go-pkcs12)](https://pkg.go.dev/github.com/ggpslop/go-pkcs12)

    import "github.com/ggpslop/go-pkcs12"

This package is forked from `software.sslmate.com/src/go-pkcs12`, which doesn't support a very flexible PKCS12 API.
It implements exactly the same API as `software.sslmate.com/src/go-pkcs12`, but adds a Builder that allows the construction of an arbitrarily complex PKCS12 (multiple PrivateKeyEntries + multiple TrustedCertificateEntry + friendly names / aliases).

Note that only DER-encoded PKCS#12 files are supported, even though PKCS#12
allows BER encoding. This is because encoding/asn1 only supports DER.

## Import Path

Note that although the source code and issue tracker for this package are hosted
on GitHub, the import path is:

    github.com/ggpslop/go-pkcs12 

Please be sure to use this path when you `go get` and `import` this package.

## Report Issues / Send Patches

Open an issue or PR at https://github.com/ggpslop/go-pkcs12
