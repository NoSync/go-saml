package saml

import (
	"fmt"
	"io/ioutil"
	"os"
)

func GenerateAuthnRequest(publicCertificate, privateKey, idpSSOUrl, idpSSODescriptorUrl,
idpPublicCertificate, assertionConsumerServiceUrl string) (string, error) {

	//Create a temporary file for the public certificate
	publicCertificateFile, err := ioutil.TempFile(os.TempDir(), "publicCertificate")
	if err != nil {
		return "", err
	}
	publicCertificatePath := publicCertificateFile.Name()
	defer deleteTempFile(publicCertificatePath)

	//Create a temporary file for the private key
	privateKeyFile, err := ioutil.TempFile(os.TempDir(), "privateKey")
	if err != nil {
		return "", err
	}
	privateKeyPath := privateKeyFile.Name()
	defer deleteTempFile(privateKeyPath)

	//Create a temporary file for the idp public certificate
	idpPublicCertificateFile, err := ioutil.TempFile(os.TempDir(), "privateKey")
	if err != nil {
		return "", err
	}
	idpPublicCertificatePath := idpPublicCertificateFile.Name()
	defer deleteTempFile(idpPublicCertificatePath)

	sp := ServiceProviderSettings{
		PublicCertPath:              publicCertificatePath,
		PrivateKeyPath:              privateKeyPath,
		IDPSSOURL:                   idpSSOUrl,
		IDPSSODescriptorURL:         idpSSODescriptorUrl,
		IDPPublicCertPath:           idpPublicCertificatePath,
		AssertionConsumerServiceURL: assertionConsumerServiceUrl,
	}
	err = sp.Init()
	if err != nil {
		return "", err
	}

	// generate the AuthnRequest and then get a base64 encoded string of the XML
	authnRequest := sp.GetAuthnRequest()
	b64XML, err := authnRequest.EncodedSignedString(sp.PrivateKeyPath)
	if err != nil {
		return "", err
	}
	return b64XML, nil
}

func GenerateSamlResponse(response *Response, publicCertificate, privateKey, idpSSOUrl,
idpSSODescriptorUrl, idpPublicCertificate, assertionConsumerServiceUrl string) (error) {

	//Create a temporary file for the public certificate
	publicCertificateFile, err := ioutil.TempFile(os.TempDir(), "publicCertificate")
	if err != nil {
		return err
	}
	publicCertificatePath := publicCertificateFile.Name()
	defer deleteTempFile(publicCertificatePath)

	//Create a temporary file for the private key
	privateKeyFile, err := ioutil.TempFile(os.TempDir(), "privateKey")
	if err != nil {
		return err
	}
	privateKeyPath := privateKeyFile.Name()
	defer deleteTempFile(privateKeyPath)

	//Create a temporary file for the idp public certificate
	idpPublicCertificateFile, err := ioutil.TempFile(os.TempDir(), "privateKey")
	if err != nil {
		return  err
	}
	idpPublicCertificatePath := idpPublicCertificateFile.Name()
	defer deleteTempFile(idpPublicCertificatePath)

	sp := ServiceProviderSettings{
		PublicCertPath:              publicCertificatePath,
		PrivateKeyPath:              privateKeyPath,
		IDPSSOURL:                   idpSSOUrl,
		IDPSSODescriptorURL:         idpSSODescriptorUrl,
		IDPPublicCertPath:           idpPublicCertificatePath,
		AssertionConsumerServiceURL: assertionConsumerServiceUrl,
	}
	sp.Init()
	if err != nil {
		return err
	}

	err = response.Validate(&sp)
	if err != nil {
		return fmt.Errorf("SAMLResponse validation: "+err.Error())
	}
	return nil
}