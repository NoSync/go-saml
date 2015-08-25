package saml

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSignedRequest(t *testing.T) {
	assert := assert.New(t)

	b, err := ioutil.ReadFile("./default.crt")
	assert.NoError(err)
	publicCert := string(b)

	b, err = ioutil.ReadFile("./default.key")
	assert.NoError(err)
	privateKey := string(b)

	b, err = ioutil.ReadFile("./default.crt")
	assert.NoError(err)
	iDPPublicCert := string(b)

	sp := ServiceProviderSettings{
		PublicCert:                  publicCert,
		PrivateKey:                  privateKey,
		IDPSSOURL:                   "http://www.onelogin.net",
		IDPSSODescriptorURL:         "http://www.onelogin.net",
		IDPPublicCert:               iDPPublicCert,
		AssertionConsumerServiceURL: "http://localhost:8000/auth/saml/name",
	}
	err = sp.Init()
	assert.NoError(err)

	// Construct an AuthnRequest
	authnRequest := sp.GetAuthnRequest()
	signedXML, err := authnRequest.SignedString(sp.PrivateKey)
	assert.NoError(err)
	assert.NotEmpty(signedXML)

	err = VerifyRequestSignature(signedXML, sp.PublicCert)
	assert.NoError(err)
}
