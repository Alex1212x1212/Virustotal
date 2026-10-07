package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	vtBaseURL    = "https://www.virustotal.com/api/v3"
	maxFileSize  = 32 * 1024 * 1024 // 32MB
	pollInterval = 16 * time.Second
	fastPoll     = 2 * time.Second
)

type VirusTotalAPI struct {
	APIKey      string
	IsPublicAPI bool
	client      *http.Client
}

func NewVirusTotalAPI(apiKey string, isPublic bool) *VirusTotalAPI {
	return &VirusTotalAPI{
		APIKey:      apiKey,
		IsPublicAPI: isPublic,
		client: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

func (api *VirusTotalAPI) doRequest(req *http.Request) ([]byte, error) {
	req.Header.Set("x-apikey", api.APIKey)
	resp, err := api.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 200 {
		return body, nil
	} else if resp.StatusCode == 404 {
		return nil, nil // Not found
	} else if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limit exceeded")
	}

	return nil, fmt.Errorf("API Error %d: %s", resp.StatusCode, string(body))
}

func (api *VirusTotalAPI) GetFileReport(fileHash string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/files/%s", vtBaseURL, fileHash)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	body, err := api.doRequest(req)
	if err != nil || body == nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (api *VirusTotalAPI) UploadFile(filepathStr string) (string, error) {
	info, err := os.Stat(filepathStr)
	if err != nil {
		return "", err
	}
	if info.Size() > maxFileSize {
		return "", fmt.Errorf("file too large (%.2fMB). Max 32MB", float64(info.Size())/1024/1024)
	}

	file, err := os.Open(filepathStr)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)
	part, err := writer.CreateFormFile("file", filepath.Base(filepathStr))
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(part, file); err != nil {
		return "", err
	}
	writer.Close()

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/files", vtBaseURL), &requestBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	body, err := api.doRequest(req)
	if err != nil {
		return "", err
	}

	var result struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	return result.Data.ID, nil
}

func (api *VirusTotalAPI) WaitForAnalysis(analysisID string, statusCb func(string)) (string, error) {
	url := fmt.Sprintf("%s/analyses/%s", vtBaseURL, analysisID)
	
	interval := pollInterval
	if !api.IsPublicAPI {
		interval = fastPoll
	}

	attempts := int(600 / interval.Seconds())
	for i := 0; i < attempts; i++ {
		req, err := http.NewRequest("GET", url, nil)
		if err == nil {
			body, err := api.doRequest(req)
			if err != nil {
				if err.Error() == "rate limit exceeded" {
					statusCb("Rate limit hit. Pausing...")
				}
			} else if body != nil {
				var result struct {
					Data struct {
						Attributes struct {
							Status string `json:"status"`
						} `json:"attributes"`
					} `json:"data"`
					Meta struct {
						FileInfo struct {
							SHA256 string `json:"sha256"`
						} `json:"file_info"`
					} `json:"meta"`
				}
				if err := json.Unmarshal(body, &result); err == nil {
					status := result.Data.Attributes.Status
					if status == "completed" {
						return result.Meta.FileInfo.SHA256, nil
					}
					statusCb(fmt.Sprintf("Analysis: %s...", status))
				}
			}
		}
		time.Sleep(interval)
	}
	return "", fmt.Errorf("analysis timed out")
}
