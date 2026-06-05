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
	enc             *Encoder
	certBags        []safeBag
	prvKeyBags      []safeBag
	trustedBags     []safeBag
	encodedPassword []byte
	aliases         map[string]struct{}
}

type PrvKeyStoreEntry struct {
	PrivateKey  any
	Certificate *x509.Certificate
	CaCerts     []*x509.Certificate
}

var (
	trustCertPkcs12Attribute = getTrustCertPkcs12Attribute()
)

// NewBuilder creates a new PKCS12 builder with a standard password.
// The password is copied, so it can be destroyed without problems.
// The '...Len' parameters are optional and can be used to preallocate memory.
func NewBuilder(enc *Encoder, password []byte, prvKeyEntryLen uint8, trustCertLen uint8) (Builder, error) {

	var err error
	var s = Builder{
		enc:     enc,
		aliases: make(map[string]struct{}, prvKeyEntryLen+trustCertLen),
	}

	if prvKeyEntryLen > 0 {
		s.certBags = make([]safeBag, 0, prvKeyEntryLen*3)
		s.prvKeyBags = make([]safeBag, 0, prvKeyEntryLen)
	}
	if trustCertLen > 0 {
		s.trustedBags = make([]safeBag, 0, trustCertLen)
	}

	if enc.macAlgorithm == nil && enc.certAlgorithm == nil && enc.keyAlgorithm == nil && len(password) != 0 {
		return Builder{}, errors.New("pkcs12: password must be empty")
	}

	s.encodedPassword, err = bmpStringZeroTerminatedFromBytes(password)
	if err != nil {
		return Builder{}, err
	}
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
// Does not check the consistency of the private key with the public key.
func (s *Builder) SetPrivateKeyEntry(friendlyName string, entry PrvKeyStoreEntry) error {

	if entry.Certificate == nil {
		return errors.New("pkcs12: empty certificate")
	}
	if entry.PrivateKey == nil {
		return errors.New("pkcs12: empty private key")
	}
	if friendlyName == "" {
		return errors.New("pkcs12: empty friendly name")
	}

	friendlyNameAttr, err := s.encodeFriendlyName(friendlyName)
	if err != nil {
		return err
	}

	var certFingerprint = sha1.Sum(entry.Certificate.Raw)
	var localKeyIdAttr pkcs12Attribute
	localKeyIdAttr.Id = oidLocalKeyID
	localKeyIdAttr.Value.Class = 0
	localKeyIdAttr.Value.Tag = 17
	localKeyIdAttr.Value.IsCompound = true
	if localKeyIdAttr.Value.Bytes, err = asn1.Marshal(certFingerprint[:]); err != nil {
		return err
	}

	if certBag, err := makeCertBag(entry.Certificate.Raw, []pkcs12Attribute{localKeyIdAttr, friendlyNameAttr}); err != nil {
		return err
	} else {
		s.certBags = append(s.certBags, *certBag)
	}

	for _, cert := range entry.CaCerts {
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
		if keyBag.Value.Bytes, err = x509.MarshalPKCS8PrivateKey(entry.PrivateKey); err != nil {
			return err
		}
	} else {
		keyBag.Id = oidPKCS8ShroundedKeyBag
		keyBag.Value.Class = 2
		keyBag.Value.Tag = 0
		keyBag.Value.IsCompound = true
		if keyBag.Value.Bytes, err = encodePkcs8ShroudedKeyBag(enc.rand, entry.PrivateKey, enc.keyAlgorithm, s.encodedPassword, enc.encryptionIterations, enc.saltLen); err != nil {
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

// Build the entire PKCS12 object in memory structured like this:
//  1. AuthenticatedSafe: PrivateKeyEntry certificates;
//  2. AuthenticatedSafe: PrivateKeyEntry private keys;
//  3. AuthenticatedSafe: Trusted certificates.
//
// Erase the internal encoded copy of the password regardless of the result.
func (s *Builder) Build() (pfxData []byte, err error) {
	defer zeroingBytes(s.encodedPassword)

	var enc = s.enc
	var pfx pfxPdu
	pfx.Version = 3

	var authenticatedSafe = make([]contentInfo, 0, 3)

	// Add Trusted Certificates.
	if len(s.trustedBags) != 0 {
		ci, err := makeSafeContents(enc.rand, s.trustedBags, enc.certAlgorithm, s.encodedPassword, enc.encryptionIterations, enc.saltLen)
		if err != nil {
			return nil, err
		}
		authenticatedSafe = append(authenticatedSafe, ci)
	}

	// Add Certificates with their Private Keys and Chains.
	if len(s.certBags) != 0 {
		ci, err := makeSafeContents(enc.rand, s.certBags, enc.certAlgorithm, s.encodedPassword, enc.encryptionIterations, enc.saltLen)
		if err != nil {
			return nil, err
		}
		authenticatedSafe = append(authenticatedSafe, ci)

		ci, err = makeSafeContents(enc.rand, s.prvKeyBags, nil, nil, 0, 0)
		if err != nil {
			return nil, err
		}
		authenticatedSafe = append(authenticatedSafe, ci)
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
