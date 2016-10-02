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
	"encoding/asn1"
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

// ContentInfo
type ContentInfo struct {
	ContentId       string
	ContentName     string
	ContentProvider string
	ContentPrice    string
}

// licence info
type LicenceInfo struct {
	ContentName     string
	ContentProvider string
	ContentPrice    string
	HasLicence      bool
}

// AssetManagementChaincode is simple chaincode implementing a basic Asset Management system
// with access control enforcement at chaincode level.
// Look here for more information on how to implement access control at chaincode level:
// https://github.com/hyperledger/fabric/blob/master/docs/tech/application-ACL.md
// An asset is simply represented by a string.
type ContentDeliveryChaincode struct {
}

// We didn't set the binding yet. So this is useless.
func (t *ContentDeliveryChaincode) verifySignature(stub shim.ChaincodeStubInterface) (bool, error) {
	// Unmarshall metadata
	metadata, err := stub.GetCallerMetadata()
	cdMetadata := new(CDMetadata)
	_, err = asn1.Unmarshal(metadata, cdMetadata)
	if err != nil {
		return false, fmt.Errorf("Failed unmarshalling metadata [%s]", err)
	}

	// Verify signature
	payload, err := stub.GetPayload()
	if err != nil {
		return false, errors.New("Failed getting payload")
	}
	binding, err := stub.GetBinding()
	if err != nil {
		return false, errors.New("Failed getting binding")
	}

	myLogger.Debug("passed certificate [% x]", cdMetadata.Cert)
	myLogger.Debug("passed sigma [% x]", cdMetadata.Sigma)
	myLogger.Debug("passed payload [% x]", payload)
	myLogger.Debug("passed binding [% x]", binding)

	ok, err := stub.VerifySignature(
		cdMetadata.Cert,
		cdMetadata.Sigma,
		append(cdMetadata.Cert, append(payload, binding...)...),
	)
	if err != nil {
		return false, fmt.Errorf("Failed verifying signature [%s]", err)
	}
	if !ok {
		return false, fmt.Errorf("Signature is not valid!")
	}

	myLogger.Debug("Signature verified")
	return true, nil
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
		&shim.ColumnDefinition{Name: "ContentName", Type: shim.ColumnDefinition_STRING, Key: false},
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

	if len(args) != 4 {
		return nil, errors.New("Incorrect number of arguments. Expecting 4")
	}

	contentId := args[0]
	contentName := args[1]
	providerId := args[2]
	contentPrice := args[3]

	// Register content
	myLogger.Debugf("New content publish of [%s, %s, %s, %s]", contentId, contentName, providerId, contentPrice)

	ok, err := stub.InsertRow("ContentOwnership", shim.Row{
		Columns: []*shim.Column{
			&shim.Column{Value: &shim.Column_String_{String_: contentId}},
			&shim.Column{Value: &shim.Column_String_{String_: contentName}},
			&shim.Column{Value: &shim.Column_String_{String_: providerId}},
			&shim.Column{Value: &shim.Column_String_{String_: contentPrice}}},
	})

	if !ok && err == nil {
		return nil, errors.New("Content was already published.")
	}

	return nil, nil
}

func (t *ContentDeliveryChaincode) buyContent(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	myLogger.Debug("Buy Content...")

	if len(args) != 3 {
		return nil, errors.New("Incorrect number of arguments. Expecting 2")
	}

	transactionId := args[0]
	userId := args[1]
	ContentId := args[2]

	// TODO: find out how to get trasaction(user pay for content) result.

	// Register content authrity
	myLogger.Debugf("New content authrity [%s, %s]", userId, ContentId)

	ok, err := stub.InsertRow("ContentAuthority", shim.Row{
		Columns: []*shim.Column{
			&shim.Column{Value: &shim.Column_String_{String_: userId}},
			&shim.Column{Value: &shim.Column_String_{String_: ContentId}},
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
	} else if function == "buyContent" {
		return t.buyContent(stub, args)
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
	var allContents []*ContentInfo
	for {
		select {
		case row, ok := <-rowChannel:
			if !ok {
				rowChannel = nil
			} else {
				rows = append(rows, row)
				myLogger.Debugf("Query all contents get row %v", row.Columns)
				allContents = append(allContents, &ContentInfo{
					ContentId:       row.Columns[0].GetString_(),
					ContentName:     row.Columns[1].GetString_(),
					ContentProvider: row.Columns[2].GetString_(),
					ContentPrice:    row.Columns[3].GetString_(),
				})
			}
		}
		if rowChannel == nil {
			break
		}
	}

	myLogger.Debugf("Query done about all contents in system, get %v results", len(allContents))
	//	for i, _ := range allContents {
	//		myLogger.Debugf("Query all contents get: %v", *allContents[i])
	//	}

	contentsBytes, err := json.Marshal(allContents)
	if err != nil {
		return nil, fmt.Errorf("Failed marshal all contents: %v", err)
	}
	fmt.Println(string(contentsBytes))
	return contentsBytes, nil
}

func (t *ContentDeliveryChaincode) queryMyContents(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	myLogger.Debugf("Query contents of user")

	if len(args) != 1 {
		myLogger.Debug("Incorrect number of arguments. Expecting name of user to query")
		return nil, errors.New("Incorrect number of arguments. Expecting name of user to query")
	}

	allContentsByte, _ := t.queryAllContents(stub, []string{})

	allContents := []*ContentInfo{}
	err := json.Unmarshal(allContentsByte, &allContents)
	if err != nil {
		myLogger.Errorf("unmarshal all contents error: %v", err)
	}
	for i, _ := range allContents {
		myLogger.Debugf("Query my contents get: %v", *allContents[i])
	}

	userContents := make(map[string]*LicenceInfo)
	for _, content := range allContents {
		userContents[content.ContentId] = &LicenceInfo{content.ContentName, content.ContentProvider, content.ContentPrice, false}
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
		_, ok := userContents[content]
		if ok {
			userContents[content].HasLicence = true
		}
	}
	for cId, licence := range userContents {
		myLogger.Debugf("Query get licence info of user %s: %v, %v", userId, cId, *licence)
	}

	contentsBytes, _ := json.Marshal(userContents)
	return contentsBytes, nil
}

func (t *ContentDeliveryChaincode) queryLicence(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	myLogger.Debugf("Query licence")

	if len(args) != 2 {
		myLogger.Debug("Incorrect number of arguments. Expecting 2")
		return nil, errors.New("Incorrect number of arguments. Expecting 2")
	}

	userId := args[0]
	ContentId := args[1]

	var columns []shim.Column
	col1 := shim.Column{Value: &shim.Column_String_{String_: userId}}
	col2 := shim.Column{Value: &shim.Column_String_{String_: ContentId}}
	columns = append(columns, col1)
	columns = append(columns, col2)

	row, err := stub.GetRow("ContentAuthority", columns)
	if err != nil {
		return nil, fmt.Errorf("Failed retrieving content licence: [%s]", err)
	}
	myLogger.Debugf("Query licence of content %s for user %s: %v", ContentId, userId, row)

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
	} else if function == "queryLicence" {
		return t.queryLicence(stub, args)
	} else if function == "queryAllContents" {
		return t.queryAllContents(stub, args)
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
