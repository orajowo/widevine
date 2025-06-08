package widevine

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// PsshBox parses a Widevine PSSH box and returns its payload (protobuf data).
func PsshBox(pssh []byte) ([]byte, error) {
	// PSSH box minimum size: 4 (size) + 4 (type "pssh") + 1 (version) + 3 (flags) + 16 (SystemID) + 4 (dataSize)
	// Even for version 0, we need at least 32 bytes for the fixed header + dataSize.
	if len(pssh) < 32 {
		return nil, fmt.Errorf("pssh data too short: expected at least 32 bytes, got %d", len(pssh))
	}

	// Check if it's a "pssh" box.
	if string(pssh[4:8]) != "pssh" {
		return nil, fmt.Errorf("not a pssh box: found type '%s'", string(pssh[4:8]))
	}

	version := pssh[8]
	fmt.Printf("PSSH Box Version: %d\n", version)
	if version != 0 && version != 1 {
		return nil, fmt.Errorf("unsupported pssh version %d: only versions 0 and 1 are supported", version)
	}

	// Widevine System ID: ED EF 8B A9 79 D6 4A CE A3 C8 27 DC D5 1D 21 ED
	widevineSystemID := []byte{0xED, 0xEF, 0x8B, 0xA9, 0x79, 0xD6, 0x4A, 0xCE, 0xA3, 0xC8, 0x27, 0xDC, 0xD5, 0x1D, 0x21, 0xED}
	systemID := pssh[12:28]
	if !bytes.Equal(systemID, widevineSystemID) {
		return nil, fmt.Errorf("not a widevine systemID: found %X", systemID)
	}

	dataSizeOffset := 28 // Default offset for version 0

	if version == 1 {
		// Version 1 has an additional 4-byte Key ID count and then N Key IDs (16 bytes each).
		// The dataSizeOffset must account for these.

		// Ensure there's enough data to read the keyCount.
		if len(pssh) < 32 { // Minimum size for version 1 header before keyCount
			return nil, fmt.Errorf("pssh data too short to read key count for version 1")
		}

		// Read keyCount as a 4-byte big-endian integer.
		// Using binary.BigEndian.Uint32 is safer and more idiomatic than manual shifting.
		keyCount := binary.BigEndian.Uint32(pssh[28:32])

		// Calculate the new dataSizeOffset based on keyCount.
		dataSizeOffset = 32 + int(keyCount)*16 // 32 (fixed header) + (keyCount * 16 bytes per keyID)

		// Ensure there's enough data for the calculated offset.
		if len(pssh) < dataSizeOffset+4 { // +4 for the dataSize itself
			return nil, fmt.Errorf("pssh data too short after key IDs for version 1")
		}
	}

	// Ensure there's enough data to read the dataSize.
	if len(pssh) < dataSizeOffset+4 {
		return nil, fmt.Errorf("pssh data truncated: cannot read dataSize at offset %d", dataSizeOffset)
	}

	// Read dataSize as a 4-byte big-endian integer.
	dataSize := binary.BigEndian.Uint32(pssh[dataSizeOffset : dataSizeOffset+4])

	// Ensure there's enough data for the actual payload.
	if len(pssh) < dataSizeOffset+4+int(dataSize) {
		return nil, fmt.Errorf("pssh data truncated: payload size mismatch. Expected %d bytes, got %d", dataSize, len(pssh)-(dataSizeOffset+4))
	}

	// Extract the payload.
	payload := pssh[dataSizeOffset+4 : dataSizeOffset+4+int(dataSize)]

	return payload, nil
}
