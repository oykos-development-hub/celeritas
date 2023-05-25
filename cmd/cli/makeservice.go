package main

import (
	"errors"
	"os"
	"strings"

	"github.com/gertd/go-pluralize"
	"github.com/iancoleman/strcase"
)

func makeService(arg3 string) error {
	if arg3 == "" {
		return errors.New("you must give the service a name")
	}

	data, err := templateFS.ReadFile("templates/services/service.go.txt")
	if err != nil {
		return err
	}

	var serviceName = arg3
	var modelName = arg3
	var tableName = arg3

	plur := pluralize.NewClient()

	if plur.IsPlural(arg3) {
		serviceName = plur.Singular(arg3)
		modelName = plur.Singular(arg3)
		tableName = strings.ToLower(tableName)
	} else {
		tableName = strings.ToLower(plur.Plural(arg3))
	}

	serviceName = strcase.ToCamel(serviceName)

	fileName := cel.RootPath + "/services/" + strings.ToLower(serviceName) + ".go"
	if fileExists(fileName) {
		return errors.New(fileName + " already exists!")
	}

	service := string(data)
	service = strings.ReplaceAll(service, "$MODELNAME$", strcase.ToCamel(modelName))
	service = strings.ReplaceAll(service, "$SERVICENAME$", serviceName)
	service = strings.ReplaceAll(service, "$MODULENAME$", moduleName)

	err = copyDataToFile([]byte(service), fileName)
	if err != nil {
		return err
	}

	err = insertServiceInterface(serviceName)
	if err != nil {
		return err
	}

	dtoData, err := templateFS.ReadFile("templates/dto/dto.go.txt")
	if err != nil {
		return err
	}

	dtoFileName := cel.RootPath + "/dto/" + strings.ToLower(modelName) + ".go"
	if fileExists(dtoFileName) {
		return errors.New(dtoFileName + " already exists!")
	}

	dto := string(dtoData)
	dto = strings.ReplaceAll(dto, "$SERVICENAME$", serviceName)
	dto = strings.ReplaceAll(dto, "$MODELNAME$", strcase.ToCamel(modelName))
	dto = strings.ReplaceAll(dto, "$TABLENAME$", tableName)
	dto = strings.ReplaceAll(dto, "$MODULENAME$", moduleName)

	err = copyDataToFile([]byte(dto), dtoFileName)
	if err != nil {
		return err
	}

	return nil
}

func insertServiceInterface(serviceName string) error {
	servicedata, err := os.ReadFile(cel.RootPath + "/services/service.go")
	if err != nil {
		return err
	}
	serviceContent := string(servicedata)

	serviceInterface, err := templateFS.ReadFile("templates/services/service-interface.go.txt")
	if err != nil {
		return err
	}
	serviceInterfaceData := strings.ReplaceAll(string(serviceInterface), "$SERVICENAME$", strcase.ToCamel(serviceName))

	serviceContent += "\n" + serviceInterfaceData + "\n"

	err = copyDataToFile([]byte(serviceContent), cel.RootPath+"/services/service.go")
	if err != nil {
		return err
	}

	addImportStatement(cel.RootPath+"/services/service.go", "\""+moduleName+"/dto\"")

	return nil
}
