package utils

import "encoding/base64"

func IsBase64Encoded(originalString string) bool {
	_, err := base64.StdEncoding.DecodeString(originalString)
	// No error means the string is base64 encoded
	return err == nil
}

func Base64Encode(originalString string) string {
	originalBytes := []byte(originalString)
	return base64.URLEncoding.EncodeToString(originalBytes)
}

func Base64Decode(encodedString string) (string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedString)
	if err != nil {
		return "", err
	}

	decodedString := string(decodedBytes)

	return decodedString, nil
}
