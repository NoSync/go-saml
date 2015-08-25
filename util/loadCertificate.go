package util

import (
	"regexp"
	"strings"
)

// LoadCertificate from file system
func LoadCertificate(cert string) (string, error) {
	re := regexp.MustCompile("---(.*)CERTIFICATE(.*)---")
	cert = re.ReplaceAllString(cert, "")
	cert = strings.Trim(cert, " \n")
	cert = strings.Replace(cert, "\n", "", -1)

	return cert, nil
}
