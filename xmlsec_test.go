package saml

import (
	"encoding/xml"
	"io/ioutil"
	"testing"
	"time"
	"fmt"

	"github.com/sendgrid/go-saml/util"
	"github.com/stretchr/testify/assert"
)

func TestRequest(t *testing.T) {
	assert := assert.New(t)

	b, err := ioutil.ReadFile("./default.crt")
	assert.NoError(err)
	cert := string(b)

	cert, err = util.LoadCertificate(cert)
	assert.NoError(err)


	b, err = ioutil.ReadFile("./default.key")
	assert.NoError(err)
	key := string(b)

	// Construct an AuthnRequest
	authRequest := NewAuthnRequest()
	authRequest.Signature.KeyInfo.X509Data.X509Certificate.Cert = cert

	b, err = xml.MarshalIndent(authRequest, "", "    ")
	assert.NoError(err)
	xmlAuthnRequest := string(b)

	signedXml, err := SignRequest(xmlAuthnRequest, key)
	assert.NoError(err)
	assert.NotEmpty(signedXml)

	err = VerifyRequestSignature(signedXml, cert)
	assert.NoError(err)
}

func TestResponse(t *testing.T) {
	assert := assert.New(t)

	b, err := ioutil.ReadFile("./default.crt")
	assert.NoError(err)
	cert := string(b)

	b, err = ioutil.ReadFile("./default.key")
	assert.NoError(err)
	key := string(b)

	cert, err = util.LoadCertificate("./default.crt")
	assert.NoError(err)

	fmt.Println("you made it this far...")
	time.Sleep(2*time.Second)

	// Construct an AuthnRequest
	response := NewSignedResponse()
	response.Signature.KeyInfo.X509Data.X509Certificate.Cert = cert

	b, err = xml.MarshalIndent(response, "", "    ")
	assert.NoError(err)
	xmlResponse := string(b)

	fmt.Println("you made it this far too...")
	fmt.Println(xmlResponse)

	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(2*time.Second)

	signedXml, err := SignResponse(xmlResponse, key)
	assert.NoError(err)
	assert.NotEmpty(signedXml)

	fmt.Println("sooo good!!!")
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(2*time.Second)

	err = VerifyRequestSignature(signedXml, cert)
	assert.NoError(err)
	fmt.Println("kthxbye")
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(2*time.Second)
}
