package main

// SA-GO-01: Safe type conversion using encoding/binary
import "encoding/binary"

func readUint32(data []byte) (uint32, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("insufficient data")
	}
	return binary.BigEndian.Uint32(data[:4]), nil
}
