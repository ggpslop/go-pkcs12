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

## Example

```go
import "github.com/ggpslop/go-pkcs12"

var password = []byte("password")

// create the pkcs12 new builder. Options object is optional.
var builder, err = pkcs12.NewBuilder(pkcs12.Modern2023, password, pkcs12.Options{
    orderFirstTrusts: true,
    prvKeyEntryLen:   2,
    trustCertLen:     1,
})
if err != nil {
    panic(err)
}

// add first private key / certificate pair.
var err = builder.SetPrivateKeyEntry(
    "first_key_cert_pair",
    privateKey1,
    leafCertificate1,
    chain1,
    nil,
)
if err != nil {
    panic(err)
}

// add second private key / certificate pair.
err = builder.SetPrivateKeyEntry(
    "second_key_cert_pair",
    privateKey2,
    leafCertificate2,
    nil,
    []byte("specificPrivateKeyPassword"),
)
if err != nil {
    panic(err)
}

// add the only trusted certificate.
err = builder.SetTrustedCertificateEntry("only_trust", trustCertificate)
if err != nil {
    panic(err)
}

// build all in memory.
pfx, err := builder.Build()
if err != nil {
    panic(err)
}

// use pfx
```

## Report Issues / Send Patches

Open an issue or PR at https://github.com/ggpslop/go-pkcs12
