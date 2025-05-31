package zns

import (
	"encoding/json"
	"io"
	"log"
	"os"
)

func getTemplateFilePath(path string) map[string]string {
	templateFile, err := os.Open(path)
	if err != nil {
		log.Fatalf("Error opening template file: %v", err)
	}
	defer templateFile.Close()

	byteValue, err := io.ReadAll(templateFile)
	if err != nil {
		log.Fatalf("Error reading template file: %v", err)
	}

	var template map[string]string
	if err := json.Unmarshal(byteValue, &template); err != nil {
		log.Fatalf("Error unmarshalling template file: %v", err)
	}

	return template
}

func getPtr[A any](input A) *A {
	return &input
}
