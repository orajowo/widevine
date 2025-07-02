package widevine

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func PsshBox(pssh []byte) ([]byte, error) {
	if len(pssh) < 32 {
		return nil, fmt.Errorf("pssh data too short: expected at least 32 bytes, got %d", len(pssh))
	}
	if string(pssh[4:8]) != "pssh" {
		return nil, fmt.Errorf("not a pssh box: found type '%s'", string(pssh[4:8]))
	}
	version := pssh[8]
	if version != 0 && version != 1 {
		return nil, fmt.Errorf("unsupported pssh version %d: only versions 0 and 1 are supported", version)
	}
	widevineSystemID := []byte{0xED, 0xEF, 0x8B, 0xA9, 0x79, 0xD6, 0x4A, 0xCE, 0xA3, 0xC8, 0x27, 0xDC, 0xD5, 0x1D, 0x21, 0xED}
	systemID := pssh[12:28]
	if !bytes.Equal(systemID, widevineSystemID) {
		return nil, fmt.Errorf("not a widevine systemID: found %X", systemID)
	}
	dataSizeOffset := 28
	if version == 1 {
		if len(pssh) < 32 {
			return nil, fmt.Errorf("pssh data too short to read key count for version 1")
		}
		keyCount := binary.BigEndian.Uint32(pssh[28:32])
		dataSizeOffset = 32 + int(keyCount)*16
		if len(pssh) < dataSizeOffset+4 {
			return nil, fmt.Errorf("pssh data too short after key IDs for version 1")
		}
	}
	if len(pssh) < dataSizeOffset+4 {
		return nil, fmt.Errorf("pssh data truncated: cannot read dataSize at offset %d", dataSizeOffset)
	}
	dataSize := binary.BigEndian.Uint32(pssh[dataSizeOffset : dataSizeOffset+4])
	if len(pssh) < dataSizeOffset+4+int(dataSize) {
		return nil, fmt.Errorf("pssh data truncated: payload size mismatch. Expected %d bytes, got %d", dataSize, len(pssh)-(dataSizeOffset+4))
	}
	payload := pssh[dataSizeOffset+4 : dataSizeOffset+4+int(dataSize)]

	return payload, nil
}
