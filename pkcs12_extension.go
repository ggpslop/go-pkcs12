package pkcs12

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"runtime"
)

type Builder struct {
	enc              *Encoder
	certBags         []safeBag
	prvKeyBags       []safeBag
	trustedBags      []safeBag
	encodedPassword  []byte
	aliases          map[string]struct{}
	orderFirstTrusts bool
}

type Options struct {
	orderFirstTrusts bool
	prvKeyEntryLen   uint8
	trustCertLen     uint8
}

var (
	trustCertPkcs12Attribute = getTrustCertPkcs12Attribute()
)

// NewBuilder creates a new PKCS12 builder with a main builder password, used
// across all the PKCS12 object, except when other passwords are provided.
// The password is copied, so it can be destroyed without problems.
//
// The Options are optional. They can be used to preallocate some memory and to
// decide the build order (first trusted, then key/cert pairs, or vice versa).
func NewBuilder(enc *Encoder, password []byte, opt Options) (Builder, error) {

	var err error
	if enc == nil {
		return Builder{}, errors.New("pkcs12: encoder cannot be nil")
	}

	var s = Builder{
		enc:     enc,
		aliases: make(map[string]struct{}, opt.prvKeyEntryLen+opt.trustCertLen),
	}

	if opt.prvKeyEntryLen > 0 {
		s.certBags = make([]safeBag, 0, opt.prvKeyEntryLen*3)
		s.prvKeyBags = make([]safeBag, 0, opt.prvKeyEntryLen)
	}
	if opt.trustCertLen > 0 {
		s.trustedBags = make([]safeBag, 0, opt.trustCertLen)
	}
	if enc.macAlgorithm == nil && enc.certAlgorithm == nil && enc.keyAlgorithm == nil && len(password) != 0 {
		return Builder{}, errors.New("pkcs12: password must be empty")
	}

	s.encodedPassword, err = bmpStringZeroTerminatedFromBytes(password)
	if err != nil {
		return Builder{}, err
	}

	s.orderFirstTrusts = opt.orderFirstTrusts

	return s, nil
}

// Reset the internal state of the builder, so it can be used again for a new PKCS12.
// The password is copied, so it can be destroyed without problems.
func (s *Builder) Reset(password []byte) error {
	var err error
	var enc = s.enc
	if enc.macAlgorithm == nil && enc.certAlgorithm == nil && enc.keyAlgorithm == nil && len(password) != 0 {
		return errors.New("pkcs12: password must be empty")
	}
	clear(s.aliases)
	s.prvKeyBags = s.prvKeyBags[:0]
	s.certBags = s.certBags[:0]
	s.trustedBags = s.trustedBags[:0]
	s.encodedPassword, err = bmpStringZeroTerminatedFromBytes(password)
	return err
}

// SetPrivateKeyEntry set a certificate with its private key and an optional
// chain of trust, with a custom friendly name (alias). Private Key and Certificate
// share the same localKeyId and friendlyName.
//
// Password is optional: if not provided, the builder main password will be used.
// If it's provided, the encoded version created at run time will be erased after the end
// of this method.
//
// Does not check the consistency of the private key with the public key.
func (s *Builder) SetPrivateKeyEntry(
	friendlyName string,
	privateKey any,
	certificate *x509.Certificate,
	caCerts []*x509.Certificate,
	password []byte,
) error {

	if certificate == nil {
		return errors.New("pkcs12: empty certificate")
	}
	if privateKey == nil {
		return errors.New("pkcs12: empty private key")
	}
	if friendlyName == "" {
		return errors.New("pkcs12: empty friendly name")
	}

	friendlyNameAttr, err := s.encodeFriendlyName(friendlyName)
	if err != nil {
		return err
	}

	var certFingerprint = sha1.Sum(certificate.Raw)
	var localKeyIdAttr pkcs12Attribute
	localKeyIdAttr.Id = oidLocalKeyID
	localKeyIdAttr.Value.Class = 0
	localKeyIdAttr.Value.Tag = 17
	localKeyIdAttr.Value.IsCompound = true
	if localKeyIdAttr.Value.Bytes, err = asn1.Marshal(certFingerprint[:]); err != nil {
		return err
	}

	if certBag, err := makeCertBag(certificate.Raw, []pkcs12Attribute{localKeyIdAttr, friendlyNameAttr}); err != nil {
		return err
	} else {
		s.certBags = append(s.certBags, *certBag)
	}

	for _, cert := range caCerts {
		if certBag, err := makeCertBag(cert.Raw, []pkcs12Attribute{}); err != nil {
			return err
		} else {
			s.certBags = append(s.certBags, *certBag)
		}
	}

	var enc = s.enc
	var keyBag safeBag
	if enc.keyAlgorithm == nil {
		keyBag.Id = oidKeyBag
		keyBag.Value.Class = 2
		keyBag.Value.Tag = 0
		keyBag.Value.IsCompound = true
		if keyBag.Value.Bytes, err = x509.MarshalPKCS8PrivateKey(privateKey); err != nil {
			return err
		}
	} else {
		var encodedPass = s.encodedPassword
		if len(password) != 0 {
			if encodedPass, err = bmpStringZeroTerminatedFromBytes(password); err != nil {
				return err
			}
			defer zeroingBytes(encodedPass)
		}

		keyBag.Id = oidPKCS8ShroundedKeyBag
		keyBag.Value.Class = 2
		keyBag.Value.Tag = 0
		keyBag.Value.IsCompound = true
		if keyBag.Value.Bytes, err = encodePkcs8ShroudedKeyBag(enc.rand, privateKey, enc.keyAlgorithm, encodedPass, enc.encryptionIterations, enc.saltLen); err != nil {
			return err
		}
	}
	keyBag.Attributes = append(keyBag.Attributes, localKeyIdAttr, friendlyNameAttr)

	s.prvKeyBags = append(s.prvKeyBags, keyBag)

	return nil
}

// SetTrustedCertificateEntry set a trusted certificate with a custom friendly name (alias).
func (s *Builder) SetTrustedCertificateEntry(friendlyName string, certificate *x509.Certificate) error {

	if certificate == nil {
		return errors.New("pkcs12: empty certificate")
	}
	if friendlyName == "" {
		return errors.New("pkcs12: empty friendlyName")
	}

	encodedFriendlyName, err := s.encodeFriendlyName(friendlyName)
	if err != nil {
		return err
	}

	cBag, err := makeCertBag(certificate.Raw, []pkcs12Attribute{trustCertPkcs12Attribute, encodedFriendlyName})
	if err != nil {
		return err
	}
	s.trustedBags = append(s.trustedBags, *cBag)

	return nil
}

// Build the entire PKCS12 object in memory.
// Erase the internal encoded copy of the password regardless of the result.
func (s *Builder) Build() (pfxData []byte, err error) {
	defer zeroingBytes(s.encodedPassword)

	var enc = s.enc
	var pfx pfxPdu
	pfx.Version = 3

	var authenticatedSafe = make([]contentInfo, 0, 3)

	if s.orderFirstTrusts {
		// 1. add Trusted Certificates.
		if authenticatedSafe, err = s.addTrustedCertificates(authenticatedSafe); err != nil {
			return nil, err
		}
		// 2. add Certificates with their Private Keys and Chains.
		if authenticatedSafe, err = s.addKeyCertPair(authenticatedSafe); err != nil {
			return nil, err
		}
	} else {
		// 1. add Certificates with their Private Keys and Chains.
		if authenticatedSafe, err = s.addKeyCertPair(authenticatedSafe); err != nil {
			return nil, err
		}
		// 2. add Trusted Certificates.
		if authenticatedSafe, err = s.addTrustedCertificates(authenticatedSafe); err != nil {
			return nil, err
		}
	}

	var authenticatedSafeBytes []byte
	if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe); err != nil {
		return nil, err
	}

	if enc.macAlgorithm != nil {
		macSalt := make([]byte, enc.saltLen)
		if _, err = enc.rand.Read(macSalt); err != nil {
			return nil, err
		}
		pfx.MacData.Mac.Algorithm.Algorithm = enc.macAlgorithm
		if enc.macAlgorithm.Equal(oidPBMAC1) {
			var err error
			pfx.MacData.Mac.Algorithm.Parameters.FullBytes, err = makePBMAC1Parameters(macSalt, enc.macIterations)
			if err != nil {
				return nil, err
			}
		} else {
			pfx.MacData.MacSalt = macSalt
			pfx.MacData.Iterations = enc.macIterations
		}
		if err = computeMac(&pfx.MacData, authenticatedSafeBytes, s.encodedPassword); err != nil {
			return nil, err
		}
	}

	pfx.AuthSafe.ContentType = oidDataContentType
	pfx.AuthSafe.Content.Class = 2
	pfx.AuthSafe.Content.Tag = 0
	pfx.AuthSafe.Content.IsCompound = true
	if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
		return nil, err
	}

	if pfxData, err = asn1.Marshal(pfx); err != nil {
		return nil, fmt.Errorf("pkcs12: error writing P12 data: %w", err)
	}
	return
}

func (s *Builder) addTrustedCertificates(authenticatedSafe []contentInfo) ([]contentInfo, error) {
	if len(s.trustedBags) != 0 {
		ci, err := makeSafeContents(s.enc.rand, s.trustedBags, s.enc.certAlgorithm, s.encodedPassword, s.enc.encryptionIterations, s.enc.saltLen)
		if err != nil {
			return nil, err
		}
		return append(authenticatedSafe, ci), nil
	}
	return authenticatedSafe, nil
}

func (s *Builder) addKeyCertPair(authenticatedSafe []contentInfo) ([]contentInfo, error) {
	if len(s.certBags) != 0 {
		ci, err := makeSafeContents(s.enc.rand, s.certBags, s.enc.certAlgorithm, s.encodedPassword, s.enc.encryptionIterations, s.enc.saltLen)
		if err != nil {
			return nil, err
		}
		authenticatedSafe = append(authenticatedSafe, ci)

		ci, err = makeSafeContents(s.enc.rand, s.prvKeyBags, nil, nil, 0, 0)
		if err != nil {
			return nil, err
		}
		return append(authenticatedSafe, ci), nil
	}
	return authenticatedSafe, nil
}

func (s *Builder) encodeFriendlyName(friendlyName string) (pkcs12Attribute, error) {

	if _, exists := s.aliases[friendlyName]; exists {
		return pkcs12Attribute{}, errors.New("pkcs12: friendly name already in use")
	}
	s.aliases[friendlyName] = struct{}{}

	bmpFriendlyName, err := bmpString(friendlyName)
	if err != nil {
		return pkcs12Attribute{}, err
	}

	encodedFriendlyName, err := asn1.Marshal(asn1.RawValue{
		Class:      0,
		Tag:        30,
		IsCompound: false,
		Bytes:      bmpFriendlyName,
	})
	if err != nil {
		return pkcs12Attribute{}, err
	}

	return pkcs12Attribute{
		Id: oidFriendlyName,
		Value: asn1.RawValue{
			Class:      0,
			Tag:        17,
			IsCompound: true,
			Bytes:      encodedFriendlyName,
		},
	}, nil
}

func getTrustCertPkcs12Attribute() pkcs12Attribute {
	extKeyUsageOidBytes, err := asn1.Marshal(oidAnyExtendedKeyUsage)
	if err != nil {
		panic(fmt.Sprintf("trustPkcs12Attribute: %v", err))
	}

	// the oidJavaTrustStore attribute contains the EKUs for which
	// this trust anchor will be valid
	return pkcs12Attribute{
		Id: oidJavaTrustStore,
		Value: asn1.RawValue{
			Class:      0,
			Tag:        17,
			IsCompound: true,
			Bytes:      extKeyUsageOidBytes,
		},
	}
}

// zeroingBytes zero out the input byte slice.
func zeroingBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}

	// This should keep buf's backing array live and thus prevent dead store
	// elimination, according to discussion at
	// https://github.com/golang/go/issues/33325 .
	runtime.KeepAlive(buf)
}
