package saml

import "github.com/sendgrid/go-saml/util"

// ServiceProviderSettings provides settings to configure server acting as a SAML Service Provider.
// Expect only one IDP per SP in this configuration. If you need to configure multipe IDPs for an SP
// then configure multiple instances of this module
type ServiceProviderSettings struct {
	PublicCert                  string
	PrivateKey                  string
	IDPSSOURL                   string
	IDPSSODescriptorURL         string
	IDPPublicCert               string
	AssertionConsumerServiceURL string

	hasInit       bool
}

type IdentityProviderSettings struct {
}

func (s *ServiceProviderSettings) Init() (err error) {
	if s.hasInit {
		return nil
	}
	s.hasInit = true

	s.PublicCert, err = util.LoadCertificate(s.PublicCert)
	if err != nil {
		panic(err)
	}

	s.PrivateKey, err = util.LoadCertificate(s.PrivateKey)
	if err != nil {
		panic(err)
	}

	s.IDPPublicCert, err = util.LoadCertificate(s.IDPPublicCert)
	if err != nil {
		panic(err)
	}

	return nil
}

