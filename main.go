package findmydecoder

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
)

// DecodedReport represents a decoded report
type DecodedReport struct {
	Latitude   float64 `json:"lat"`
	Longitude  float64 `json:"lon"`
	Confidence int     `json:"conf"`
	// usually this is the status of the battery, but it can be used to transmit other data from a tag
	Status    int       `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// DecodeReport decodes the payload of a report, decrypts it, and on success returns a DecodedReport.
// Decoding can fail if apple has changed their payload encoding or the provided private key is incorrect
func DecodeReport(payload []byte, privateKey []byte) (*DecodedReport, error) {
	// some versions include an extra byte that needs to be removed
	if len(payload) > 88 {
		payload = append(payload[:4], payload[5:]...)
	}

	decrypted, err := decryptPayload(payload, privateKey)
	if err != nil {
		return nil, fmt.Errorf("error decrypting payload: %w", err)
	}

	decoded := decodeDecryptedReportData(decrypted)
	decoded.Timestamp = time.UnixMicro(int64(binary.BigEndian.Uint32(payload[0:4])) + 978307200) // Apple epoch

	return &decoded, nil
}

// decryptPayload decrypts a find my payload gotten from a location report.
//
// Directly accepts bytes from the payload field of a find my location report.
// On success it returns the decrypted data.
// Will return nil and an error if the private key does not match the data.
func decryptPayload(data []byte, privateKeyBytes []byte) ([]byte, error) {
	ephX, ephY, err := extractEphemeralKey(data)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling ephemeral public key: %w", err)
	}

	priv := createPrivateKey(privateKeyBytes)

	sharedKey := deriveSharedKey(priv, ephX, ephY)
	symmetricKey := calculateSymmetricKey(sharedKey, data[5:62])

	decryptionKey, iv, encData, tag := prepareDecryptionInputs(symmetricKey, data)
	decrypted, err := decrypt(encData, decryptionKey, iv, tag)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return decrypted, nil
}

// CreatePrivateKey creates an ECDSA private key from bytes.
func createPrivateKey(privKeyBytes []byte) *ecdsa.PrivateKey {
	curve := elliptic.P224()
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = new(big.Int).SetBytes(privKeyBytes)
	return priv
}

// extractEphemeralKey extracts and unmarshals the ephemeral public key from a report payload.
func extractEphemeralKey(data []byte) (*big.Int, *big.Int, error) {
	curve := elliptic.P224()
	ephKeyBytes := data[5:62]
	ephX, ephY := elliptic.Unmarshal(curve, ephKeyBytes)
	if ephX == nil {
		return nil, nil, fmt.Errorf("error unmarshaling ephemeral public key")
	}
	return ephX, ephY, nil
}

// deriveSharedKey derives the shared key from the private and ephemeral public keys.
func deriveSharedKey(priv *ecdsa.PrivateKey, ephX, ephY *big.Int) []byte {
	curve := elliptic.P224()
	sharedKeyX, _ := curve.ScalarMult(ephX, ephY, priv.D.Bytes())
	keyBytes := make([]byte, (curve.Params().BitSize+7)/8)
	sharedKeyX.FillBytes(keyBytes)
	return keyBytes
}

// calculateSymmetricKey calculates the symmetric key using SHA256.
func calculateSymmetricKey(sharedKey, ephKeyBytes []byte) []byte {
	h := sha256.New()
	h.Write(sharedKey)
	h.Write([]byte{0x00, 0x00, 0x00, 0x01})
	h.Write(ephKeyBytes)
	return h.Sum(nil)
}

// prepareDecryptionInputs seperates out the key, IV, encrypted data, and tag for decryption.
func prepareDecryptionInputs(symmetricKey, data []byte) ([]byte, []byte, []byte, []byte) {
	decryptionKey := symmetricKey[:16]
	iv := symmetricKey[16:]
	encData := data[62:72]
	tag := data[72:]
	return decryptionKey, iv, encData, tag
}

// Decrypt performs AES-GCM decryption
func decrypt(ciphertext, key, nonce, tag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, append(ciphertext, tag...), nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// decodeDecryptedReportData decodes the decrypted data from a find my report
func decodeDecryptedReportData(data []byte) DecodedReport {
	latitude := float64(int32(binary.BigEndian.Uint32(data[0:4]))) / 10000000.0
	longitude := float64(int32(binary.BigEndian.Uint32(data[4:8]))) / 10000000.0
	confidence := int(data[8])
	status := int(data[9])
	return DecodedReport{Latitude: latitude, Longitude: longitude, Confidence: confidence, Status: status}
}
