/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/op/go-logging"
)

var myLogger = logging.MustGetLogger("content_delivery")

// CDMetadata metadata structure for ContentDelivery information
type CDMetadata struct {
	Cert  []byte
	Sigma []byte
}

// AssetManagementChaincode is simple chaincode implementing a basic Asset Management system
// with access control enforcement at chaincode level.
// Look here for more information on how to implement access control at chaincode level:
// https://github.com/hyperledger/fabric/blob/master/docs/tech/application-ACL.md
// An asset is simply represented by a string.
type ContentDeliveryChaincode struct {
}

// Init method will be called during deployment.
// The deploy transaction metadata is supposed to contain the administrator cert
func (t *ContentDeliveryChaincode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	myLogger.Debug("Init Chaincode...")
	if len(args) != 0 {
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}

	// Create ownership table
	err := stub.CreateTable("ContentOwnership", []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: "ContentId", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "ProviderId", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "ContentPrice", Type: shim.ColumnDefinition_STRING, Key: false},
	})
	if err != nil {
		return nil, errors.New("Failed creating ContentOwnership table.")
	} else {
		myLogger.Debug("Create ContentOwnership table.")
	}

	// Create authority table
	err = stub.CreateTable("ContentAuthority", []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: "UserId", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "ContentId", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "TransactionId", Type: shim.ColumnDefinition_STRING, Key: false},
	})
	if err != nil {
		return nil, errors.New("Failed creating ContentAuthority table.")
	} else {
		myLogger.Debug("Create ContentAuthority table.")
	}

	myLogger.Debug("Init Chaincode...done")

	return nil, nil
}

func (t *ContentDeliveryChaincode) publishContent(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	myLogger.Debug("Publish Content...")

	if len(args) != 3 {
		return nil, errors.New("Incorrect number of arguments. Expecting 3")
	}

	contentId := args[0]
	providerId := args[1]
	contentPrice := args[2]

	// Register content
	myLogger.Debugf("New content publish of [%s, %s, %s]", providerId, contentId, contentPrice)

	ok, err := stub.InsertRow("ContentOwnership", shim.Row{
		Columns: []*shim.Column{
			&shim.Column{Value: &shim.Column_String_{String_: contentId}},
			&shim.Column{Value: &shim.Column_String_{String_: providerId}},
			&shim.Column{Value: &shim.Column_String_{String_: contentPrice}}},
	})

	if !ok && err == nil {
		return nil, errors.New("Content was already published.")
	}

	return nil, nil
}

func (t *ContentDeliveryChaincode) authrityContent(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	myLogger.Debug("Authority Content...")

	if len(args) != 3 {
		return nil, errors.New("Incorrect number of arguments. Expecting 2")
	}

	transactionId := args[0]
	userId := args[1]
	contentId := args[2]

	// TODO: find out how to get trasaction(user pay for content) result.

	// Register content authrity
	myLogger.Debugf("New content authrity [%s, %s]", userId, contentId)

	ok, err := stub.InsertRow("ContentAuthority", shim.Row{
		Columns: []*shim.Column{
			&shim.Column{Value: &shim.Column_String_{String_: userId}},
			&shim.Column{Value: &shim.Column_String_{String_: contentId}},
			&shim.Column{Value: &shim.Column_String_{String_: transactionId}}},
	})

	if ok && err == nil {
		return nil, nil
	}

	if !ok && err == nil {
		return nil, errors.New("Content was already authoritied.")
	}
	return nil, errors.New("unexpected error")
}

// Invoke will be called for every transaction.
// Supported functions are the following:
// "assign(asset, owner)": to assign ownership of assets. An asset can be owned by a single entity.
// Only an administrator can call this function.
// "transfer(asset, newOwner)": to transfer the ownership of an asset. Only the owner of the specific
// asset can call this function.
// An asset is any string to identify it. An owner is representated by one of his ECert/TCert.
func (t *ContentDeliveryChaincode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	myLogger.Debugf("Invode func %s", function)
	// Handle different functions
	if function == "publishContent" {
		return t.publishContent(stub, args)
	} else if function == "authrityContent" {
		return t.authrityContent(stub, args)
	}

	return nil, errors.New("Received unknown function invocation")
}

func (t *ContentDeliveryChaincode) queryAllContents(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	myLogger.Debugf("Query all contents in system")

	if len(args) != 0 {
		myLogger.Debug("Incorrect number of arguments. Expecting 0")
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}

	columns := []shim.Column{}

	rowChannel, err := stub.GetRows("ContentOwnership", columns)
	if err != nil {
		myLogger.Debugf("Failed retriving all contents in system: %v", err)
		return nil, fmt.Errorf("Failed retriving all contents in system: %v", err)
	}

	var rows []shim.Row
	var allContents []string
	for {
		select {
		case row, ok := <-rowChannel:
			if !ok {
				rowChannel = nil
			} else {
				rows = append(rows, row)
				myLogger.Debugf("Query all contents get row %v", row.Columns)
				allContents = append(allContents, row.Columns[0].GetString_())
			}
		}
		if rowChannel == nil {
			break
		}
	}

	myLogger.Debugf("Query done about all contents in system, get %v results", len(allContents))

	contentsBytes, _ := json.Marshal(allContents)
	return contentsBytes, nil
}

func (t *ContentDeliveryChaincode) queryMyContents(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	myLogger.Debugf("Query contents of user")

	if len(args) != 1 {
		myLogger.Debug("Incorrect number of arguments. Expecting name of user to query")
		return nil, errors.New("Incorrect number of arguments. Expecting name of user to query")
	}

	allContentsByte, _ := t.queryAllContents(stub, []string{})

	allContents := []*string{}
	err := json.Unmarshal(allContentsByte, &allContents)
	if err != nil {
		myLogger.Errorf("unmarshal all contents error: %v", err)
	}
	myLogger.Debugf("Query all contents get: %v", allContents)

	userContents := make(map[string]bool)
	for _, content := range allContents {
		userContents[*content] = false
	}

	userId := args[0]

	myLogger.Debugf("Query contents of user: [%s]", userId)

	var columns []shim.Column
	col1 := shim.Column{Value: &shim.Column_String_{String_: userId}}
	columns = append(columns, col1)

	rowChannel, err := stub.GetRows("ContentAuthority", columns)
	if err != nil {
		myLogger.Debugf("Failed retriving contents of [%s]: %v", userId, err)
		return nil, fmt.Errorf("Failed retriving contents of [%s]: %v", userId, err)
	}

	var rows []shim.Row
	var myContents []string
	for {
		select {
		case row, ok := <-rowChannel:
			if !ok {
				rowChannel = nil
			} else {
				rows = append(rows, row)
				myLogger.Debugf("Query user contents get row %v", row.Columns)
				myContents = append(myContents, row.Columns[1].GetString_())
			}
		}
		if rowChannel == nil {
			break
		}
	}

	myLogger.Debugf("Query done about contents of user %s: %v", userId, myContents)

	for _, content := range myContents {
		userContents[content] = true
	}

	contentsBytes, _ := json.Marshal(userContents)
	return contentsBytes, nil
}

func (t *ContentDeliveryChaincode) queryAuthority(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	myLogger.Debugf("Query authority")

	if len(args) != 2 {
		myLogger.Debug("Incorrect number of arguments. Expecting 2")
		return nil, errors.New("Incorrect number of arguments. Expecting 2")
	}

	userId := args[0]
	contentId := args[1]

	var columns []shim.Column
	col1 := shim.Column{Value: &shim.Column_String_{String_: userId}}
	col2 := shim.Column{Value: &shim.Column_String_{String_: contentId}}
	columns = append(columns, col1)
	columns = append(columns, col2)

	row, err := stub.GetRow("ContentAuthority", columns)
	if err != nil {
		return nil, fmt.Errorf("Failed retrieving content authority: [%s]", err)
	}
	myLogger.Debugf("Query authority of content %s for user %s: %v", contentId, userId, row)

	if len(row.Columns) == 0 {
		return []byte("no"), nil
	}
	return []byte("yes"), nil
}

// Query callback representing the query of a chaincode
// Supported functions are the following:
// "query(asset)": returns the owner of the asset.
// Anyone can invoke this function.
func (t *ContentDeliveryChaincode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	myLogger.Debugf("Query [%s]", function)

	// Handle different functions
	if function == "queryMyContents" {
		return t.queryMyContents(stub, args)
	} else if function == "queryAuthority" {
		return t.queryAuthority(stub, args)
	}

	return nil, errors.New("Received unknown query function")
}

func main() {
	primitives.SetSecurityLevel("SHA3", 256)
	err := shim.Start(new(ContentDeliveryChaincode))
	if err != nil {
		fmt.Printf("Error starting ContentDeliveryChaincode: %s", err)
	}
}
