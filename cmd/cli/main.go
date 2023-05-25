package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	"github.com/emirkosuta/celeritas"
	"github.com/fatih/color"
)

const version = "1.0.0"

var moduleName string
var cel celeritas.Celeritas

func main() {
	var message string
	arg1, arg2, arg3, err := validateInput()
	if err != nil {
		exitGracefully(err)
	}

	setup(arg1)

	switch arg1 {
	case "help":
		showHelp()
	case "new":
		if arg2 == "" {
			exitGracefully(errors.New("make requires a subcommand: (migration|model|handler)"))
		}
		err = doNew(arg2)
		if err != nil {
			exitGracefully(err)
		}

	case "version":
		color.Yellow("Application version: " + version)

	case "migrate":
		if arg2 == "" {
			arg2 = "up"
		}
		err = doMigrate(arg2, arg3)
		if err != nil {
			exitGracefully(err)
		}
		message = "Migrations complete!"

	case "make":
		if arg2 == "" {
			exitGracefully(errors.New("make requires a subcommand: (migration|model|handler)"))
		}
		err = doMake(arg2, arg3)
		if err != nil {
			exitGracefully(err)
		}

	default:
		showHelp()
	}

	exitGracefully(nil, message)
}

func validateInput() (string, string, string, error) {
	var arg1, arg2, arg3 string

	if len(os.Args) > 1 {
		arg1 = os.Args[1]

		if len(os.Args) >= 3 {
			arg2 = os.Args[2]
		}

		if len(os.Args) >= 4 {
			arg3 = os.Args[3]
		}
	} else {
		showHelp()
		return "", "", "", errors.New("command required")
	}

	return arg1, arg2, arg3, nil
}

func exitGracefully(err error, msg ...string) {
	message := ""
	if len(msg) > 0 {
		message = msg[0]
	}

	if err != nil {
		showHelp()
		color.Red("Error: %v\n", err)
	}

	if len(message) > 0 {
		color.Yellow(message)
	} else {
		color.Green("Finished!")
	}

	os.Exit(0)
}

func addImportStatement(filename, importStatement string) error {
	// Read the content of the file
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	// Convert the content to a string
	fileContent := string(content)

	// Check if the import statement already exists in the file
	if strings.Contains(fileContent, importStatement) {
		return nil
	}

	// Check if the import block exists in the file
	importBlockPattern := regexp.MustCompile(`import \([\s\S]*?\)`)
	importBlockMatch := importBlockPattern.FindString(fileContent)

	// If the import block exists, add the import statement inside it
	if importBlockMatch != "" {
		importBlockEnd := strings.Index(fileContent, "\n)")
		fileContent = fileContent[:importBlockEnd] + "\n\t" + importStatement + fileContent[importBlockEnd:]
	} else {
		// If the import block doesn't exist, add a new import block
		importIndex := strings.Index(fileContent, "import")
		if importIndex == -1 {
			// If there are no imports, add the import statement after the package declaration
			packageEnd := strings.Index(fileContent, "\n\n") + 1
			fileContent = fileContent[:packageEnd] + "import (\n\t" + importStatement + "\n)\n\n" + fileContent[packageEnd:]
		} else {
			// If there are existing imports, insert the import statement in a new import block
			importBlockStart := importIndex + len("import")
			importBlock := "\nimport (\n"
			importBlock += "\t" + importStatement + "\n"
			importBlock += ")\n\n"
			fileContent = fileContent[:importBlockStart] + importBlock + fileContent[importBlockStart:]
		}
	}

	err = copyDataToFile([]byte(fileContent), filename)
	if err != nil {
		return err
	}

	return nil
}
