package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"go.uber.org/zap"
)

// makeLockRequestId generates a unique ID for a locking request.
func makeLockRequestId() string {
	machineIdBytes, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		log.Fatal("could not determine machine id", zap.Error(err))
	}
	machineId := string(machineIdBytes)

	uniqueIdBytes := make([]byte, 4)
	_, err = rand.Read(uniqueIdBytes)
	if err != nil {
		log.Fatal("could not generate lock request id", zap.Error(err))
	}
	uniqueId := hex.EncodeToString(uniqueIdBytes)

	return fmt.Sprintf("%s-%d-%s", machineId, os.Getpid(), uniqueId)
}
