package saml

import (
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

const (
	xmlResponseID = "urn:oasis:names:tc:SAML:2.0:protocol:Response"
	xmlRequestID  = "urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest"
)

// SignRequest sign a SAML 2.0 AuthnRequest
// `privateKeyPath` must be a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func SignRequest(xml string, privateKey string) (string, error) {
	return sign(xml, privateKey, xmlRequestID)
}

// SignResponse sign a SAML 2.0 Response
// `privateKey` will be written to a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func SignResponse(xml string, privateKey string) (string, error) {
	return sign(xml, privateKey, xmlResponseID)
}

func sign(xml string, privateKey string, id string) (string, error) {
	//Create a temporary file for the private key
	privateKeyFile, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}
	privateKeyPath := privateKeyFile.Name()

	defer deleteTempFile(privateKeyPath)

	_, err = privateKeyFile.WriteString(privateKey)
	if err != nil {
		return "", err
	}
	err = privateKeyFile.Close()
	if err != nil {
		return "", err
	}

	samlXmlsecInput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}
	defer deleteTempFile(samlXmlsecInput.Name())
	samlXmlsecInput.WriteString("<?xml version='1.0' encoding='UTF-8'?>\n")
	samlXmlsecInput.WriteString(xml)
	samlXmlsecInput.Close()

	samlXmlsecOutput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}
	defer deleteTempFile(samlXmlsecOutput.Name())
	samlXmlsecOutput.Close()

	// fmt.Println("xmlsec1", "--sign", "--privkey-pem", privateKeyPath,
	// 	"--id-attr:ID", id,
	// 	"--output", samlXmlsecOutput.Name(), samlXmlsecInput.Name())
	output, err := exec.Command("xmlsec1", "--sign", "--privkey-pem", privateKeyPath,
		"--id-attr:ID", id,
		"--output", samlXmlsecOutput.Name(), samlXmlsecInput.Name()).CombinedOutput()
	if err != nil {
		return "", errors.New(err.Error() + " : " + string(output))
	}

	samlSignedRequest, err := ioutil.ReadFile(samlXmlsecOutput.Name())
	if err != nil {
		return "", err
	}
	samlSignedRequestXML := strings.Trim(string(samlSignedRequest), "\n")
	return samlSignedRequestXML, nil
}

// VerifyResponseSignature verify signature of a SAML 2.0 Response document
// `publicCert` will be written to a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func VerifyResponseSignature(xml string, publicCert string) error {
	return verify(xml, publicCert, xmlResponseID)
}

// VerifyRequestSignature verify signature of a SAML 2.0 AuthnRequest document
// `publicCert` will be written to a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func VerifyRequestSignature(xml string, publicCert string) error {
	return verify(xml, publicCert, xmlRequestID)
}

func verify(xml string, publicCert string, id string) error {
	//Create a temporary file for the public certificate
	publicCertFile, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return nil
	}
	publicCertPath := publicCertFile.Name()
	defer deleteTempFile(publicCertPath)

	_, err = publicCertFile.WriteString(publicCert)
	if err != nil {
		return err
	}
	err = publicCertFile.Close()
	if err != nil {
		return err
	}

	//Write saml to
	samlXmlsecInput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return err
	}

	samlXmlsecInput.WriteString(xml)
	samlXmlsecInput.Close()
	defer deleteTempFile(samlXmlsecInput.Name())

	//fmt.Println("xmlsec1", "--verify", "--pubkey-cert-pem", publicCertPath, "--id-attr:ID", id, samlXmlsecInput.Name())
	_, err = exec.Command("xmlsec1", "--verify", "--pubkey-cert-pem", publicCertPath, "--id-attr:ID", id, samlXmlsecInput.Name()).CombinedOutput()
	if err != nil {
		return errors.New("error verifing signature: " + err.Error())
	}
	return nil
}

// deleteTempFile remove a file and ignore error
// Intended to be called in a defer after the creation of a temp file to ensure cleanup
func deleteTempFile(filename string) {
	_ = os.Remove(filename)
}
