package mailer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

var GmailSrv *gmail.Service

const (
	credentialsFile = "credentials.json"
	tokenFile       = "token.json"
)

func InitializeGmailService(ctx context.Context) error {

	b, err := os.ReadFile(credentialsFile)
	if err != nil {
		return fmt.Errorf("unable to read client secret file: %w", err)
	}

	// If modifying these scopes, delete your previously saved token.json.
	config, err := google.ConfigFromJSON(b, gmail.GmailSendScope)
	if err != nil {
		return fmt.Errorf("unable to parse client secret file to config: %w", err)
	}
	client, err := getClient(ctx, config, tokenFile)
	if err != nil {
		return fmt.Errorf("unable to get client: %w", err)
	}

	GmailSrv, err = gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return fmt.Errorf("unable to retrieve Gmail client: %w", err)
	}

	return nil
}

// Retrieve a token, saves the token, then returns the generated client.
func getClient(ctx context.Context, config *oauth2.Config, tokenFile string) (*http.Client, error) {
	tok, err := tokenFromFile(tokenFile)
	if err != nil {
		tok, err = getTokenFromWeb(ctx, config, tokenFile)
		if err != nil {
			return nil, err
		}
		err = saveToken(tokenFile, tok)
		if err != nil {
			return nil, err
		}
	}
	return config.Client(ctx, tok), nil
}

// Request a token from the web, then returns the retrieved token.
func getTokenFromWeb(ctx context.Context, config *oauth2.Config, tokenFile string) (*oauth2.Token, error) {
	tok, err := tokenFromFile(tokenFile)
	if err != nil {
		ch := make(chan string)

		go func() {
			var authCode string
			if _, err := fmt.Scan(&authCode); err != nil {
				fmt.Printf("Error reading authorization code: %v\n", err)
				os.Exit(1)
			}
			ch <- authCode // Send the authorization code to the channel
		}()

		authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
		fmt.Printf("Go to the following link in your browser then type the "+
			"authorization code: \n%v\n", authURL)

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context canceled")
		case authCode := <-ch:
			tok, err = config.Exchange(ctx, authCode)
			if err != nil {
				return nil, fmt.Errorf("unable to retrieve token from web: %w", err)
			}

			err = saveToken(tokenFile, tok)
			if err != nil {
				return nil, fmt.Errorf("unable to save token: %w", err)
			}
		}
	}
	return tok, nil
}

// Retrieves a token from a local file.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("unable to open token file: %w", err)
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	if err != nil {
		return nil, fmt.Errorf("unable to decode token file: %w", err)
	}

	return tok, err
}

// Saves a token to a file path.
func saveToken(path string, token *oauth2.Token) error {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("unable to cache oauth token: %w", err)
	}
	defer f.Close()
	err = json.NewEncoder(f).Encode(token)
	if err != nil {
		return fmt.Errorf("unable to encode token: %w", err)
	}
	return nil
}
