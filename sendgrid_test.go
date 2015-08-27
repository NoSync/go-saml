package saml

import (
	"encoding/base64"
	"io/ioutil"
	"testing"

	"github.com/sendgrid/go-saml/util"
	"github.com/stretchr/testify/assert"
)

func TestGenerateAuthnRequest(t *testing.T) {
	assert := assert.New(t)

	publicCertificatePath := "./default.crt"
	privateKeyPath := "./default.key"
	idpPublicCertificatePath := "./default.crt"

	b, err := ioutil.ReadFile(publicCertificatePath)
	assert.NoError(err)
	publicCertificate := string(b)

	b, err = ioutil.ReadFile(privateKeyPath)
	assert.NoError(err)
	privateKey := string(b)

	b, err = ioutil.ReadFile(idpPublicCertificatePath)
	assert.NoError(err)
	idpPublicCertificate := string(b)

	idpSsoUrl := "http://www.onelogin.net"
	idpSsoDescriptorUrl := "http://www.onelogin.net"
	assertionConsumerServiceUrl := "http://localhost:8000/auth/saml/name"

	b64XML, err := GenerateAuthnRequest(publicCertificate, privateKey,
		idpSsoUrl, idpSsoDescriptorUrl, idpPublicCertificate, assertionConsumerServiceUrl)

	assert.NoError(err)

	byteSignedXML, err := base64.StdEncoding.DecodeString(b64XML)
	assert.NoError(err)

	signedXML := string(byteSignedXML)

	assert.NotEmpty(signedXML)

	err = VerifyRequestSignature(signedXML, publicCertificatePath)
	assert.NoError(err)
}

func TestValidateSamlResponse(t *testing.T) {
	assert := assert.New(t)

	publicCertificatePath := "./default.crt"
	privateKeyPath := "./default.key"
	idpPublicCertificatePath := "./default.crt"

	b, err := ioutil.ReadFile(publicCertificatePath)
	assert.NoError(err)
	publicCertificate := string(b)
	publicCert, err := util.LoadCertificate(publicCertificatePath)
	assert.NoError(err)

	b, err = ioutil.ReadFile(privateKeyPath)
	assert.NoError(err)
	privateKey := string(b)

	b, err = ioutil.ReadFile(idpPublicCertificatePath)
	assert.NoError(err)
	idpPublicCertificate := string(b)

	idpSsoUrl := "http://www.onelogin.net"
	idpSsoDescriptorUrl := "http://www.onelogin.net"
	assertionConsumerServiceUrl := "http://localhost:8000/auth/saml/name"

	issuer := assertionConsumerServiceUrl
	authnResponse := NewSignedResponse()
	authnResponse.Issuer.Url = issuer
	authnResponse.Assertion.Issuer.Url = issuer
	authnResponse.Signature.KeyInfo.X509Data.X509Certificate.Cert = publicCert
	authnResponse.Assertion.Subject.NameID.Value = "180"
	authnResponse.AddAttribute("uid", "180")
	authnResponse.AddAttribute("email", "someone@domain")
	authnResponse.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo = "foo"
	authnResponse.InResponseTo = "bar"
	authnResponse.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient = issuer
	authnResponse.Destination = assertionConsumerServiceUrl

	// signed XML string
	signed, err := authnResponse.EncodedSignedString(privateKeyPath)
	assert.NoError(err)
	assert.NotEmpty(signed)

	response, err := ParseEncodedResponse(signed)
	assert.NoError(err)
	assert.NotEmpty(response)

	err = ValidateSamlResponse(response, publicCertificate, privateKey, idpSsoUrl, idpSsoDescriptorUrl, idpPublicCertificate, assertionConsumerServiceUrl)
	assert.NoError(err)
}