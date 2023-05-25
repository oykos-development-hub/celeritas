package mailer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/nsf/termbox-go"
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

func getTokenFromWeb(ctx context.Context, config *oauth2.Config, tokenFile string) (*oauth2.Token, error) {
	tok, err := tokenFromFile(tokenFile)
	if err != nil {
		ch := make(chan string)

		go func() {
			if err := termbox.Init(); err != nil {
				fmt.Printf("Error initializing termbox: %v\n", err)
				os.Exit(1)
			}
			defer termbox.Close()

			prompt := "Enter the authorization code: "
			authCode := ""
			printPrompt(prompt)

			for {
				switch ev := termbox.PollEvent(); ev.Type {
				case termbox.EventKey:
					if ev.Key == termbox.KeyEnter {
						ch <- authCode
						return
					} else if ev.Key == termbox.KeyBackspace || ev.Key == termbox.KeyBackspace2 {
						if len(authCode) > 0 {
							authCode = authCode[:len(authCode)-1]
							fmt.Printf("\r%s%s", prompt, authCode)
						}
					} else if ev.Ch != 0 {
						authCode += string(ev.Ch)
						fmt.Printf("%c", ev.Ch)
					}
				}
			}
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

	return tok, nil
}

func saveToken(path string, token *oauth2.Token) error {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("unable to cache OAuth token: %w", err)
	}
	defer f.Close()
	err = json.NewEncoder(f).Encode(token)
	if err != nil {
		return fmt.Errorf("unable to encode token: %w", err)
	}
	return nil
}

func printPrompt(prompt string) {
	fmt.Print(prompt)
	termbox.Flush()
}

func init() {
	if err := termbox.Init(); err != nil {
		fmt.Printf("Error initializing termbox: %v\n", err)
		os.Exit(1)
	}

	termbox.SetInputMode(termbox.InputEsc)
}

func cleanup() {
	termbox.Close()
}

func init() {
	if err := termbox.Init(); err != nil {
		fmt.Printf("Error initializing termbox: %v\n", err)
		os.Exit(1)
	}

	termbox.SetInputMode(termbox.InputEsc)
}
