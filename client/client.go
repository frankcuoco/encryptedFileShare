package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	userlib "github.com/cs161-staff/project2-userlib"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// Useful for string mainpulation.
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	"strconv"
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.

// This function can be safely deleted!
func someUsefulThings() {
	// Creates a random UUID
	f := userlib.UUIDNew()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Works well with Go structures!
	d, _ := userlib.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g userlib.UUID
	userlib.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// errors.New(...) creates an error type!
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)

	// Useful for string interpolation.
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// User is the structure definition for a user record.
type User struct {
	Username string
	Salt     []byte

	PKEPubEncKey  userlib.PKEEncKey
	PKEPrivDecKey userlib.PKEDecKey

	DSPubVerifyKey userlib.DSVerifyKey
	DSPrivSignKey  userlib.DSSignKey
}

type UserDatastoreOuter struct {
	UserSignature []byte
	*UserDatastore
}

type UserDatastore struct {
	PasswordHash  []byte
	Salt          []byte
	SymmKeySalt   []byte
	PKEPrivKeyEnc []byte
	DSPrivKeyEnc  []byte
}

type MailboxOuter struct {
	MAC_Tag []byte
	*Mailbox
}

type Mailbox struct {
	LocationFileEnc []byte
	PrivKeyFileEnc  []byte
	MACKeyFileEnc   []byte
	FileLength      []byte
}

type UserFileNode struct {
	MAC_Tag []byte
	*UserFileNodeData
}

type UserFileNodeData struct {
	Username        string
	LocationMailbox []byte
	PrivKeyMailbox  []byte
	MACKeyMailbox   []byte
	MACKeyNodes     []byte
	Children        []userlib.UUID
}

type Invitation struct {
	DS_Signature []byte
	*InvitationData
}
type InvitationData struct {
	LocationMailbox []byte
	ParentLocation  []byte
	PrivKeyMailbox  []byte
	MACKeyMailbox   []byte
	MACKeyNodes     []byte
}

// CIPHER TEXT SHOULD BE IN 128 BYTE BLOCKS
const FILE_BLOCK_SIZE int = 1

type File struct {
	MAC_Tag    []byte
	Ciphertext []byte
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	if len(username) < 1 {
		return nil, errors.New("Username must be greater than 1")
	}
	// TODO: This is a toy implementation.

	// Content Needed: PKE private key, DS private key, password (hashed + salted)

	// UUID(hash(username)) to get UUID (deterministic), place saltedPassword = hash(password+saltHash(username)) as value for UUID key in datastore,
	// digital signiture saltedPassword (client verification key)

	// Creates userdata struct and stores data in it. It then creates UUID
	_, ok := userlib.KeystoreGet(username + "DSPubVerifyKey")
	if ok {
		return nil, errors.New("Username/user already exists")
	}
	userdata.Username = username
	userdata.Salt = userlib.RandomBytes(32)

	usernameUUIDBytes, _ := userlib.Marshal("Username:" + username)
	usernameUUID, err := userlib.UUIDFromBytes(userlib.Hash(usernameUUIDBytes))

	passwordBytes, err := userlib.Marshal(password)
	if err != nil {
		return nil, err
	}
	saltedPassword := userlib.Argon2Key(passwordBytes, userdata.Salt, 128)

	userdata.DSPrivSignKey, userdata.DSPubVerifyKey, _ = userlib.DSKeyGen()

	userdata.PKEPubEncKey, userdata.PKEPrivDecKey, _ = userlib.PKEKeyGen()

	userlib.KeystoreSet(username+"DSPubVerifyKey", userdata.DSPubVerifyKey)
	userlib.KeystoreSet(username+"PKEPubEncKey", userdata.PKEPubEncKey)

	var passwordDataStoreFinal UserDatastoreOuter
	var passwordDataStore UserDatastore
	passwordDataStoreFinal.UserDatastore = &passwordDataStore

	passwordDataStore.SymmKeySalt = userlib.RandomBytes(32)
	userSymmKey := userlib.Argon2Key(passwordBytes, passwordDataStore.SymmKeySalt, 16)
	passwordDataStore.PasswordHash = saltedPassword
	passwordDataStore.Salt = userdata.Salt

	pkePrivKeyBytes, err := userlib.Marshal(userdata.PKEPrivDecKey)
	if err != nil {
		return nil, err
	}
	passwordDataStore.PKEPrivKeyEnc = userlib.SymEnc(userSymmKey, userlib.RandomBytes(16), pkePrivKeyBytes)

	dsPrivKeyBytes, err := userlib.Marshal(userdata.DSPrivSignKey)
	if err != nil {
		return nil, err
	}
	passwordDataStore.DSPrivKeyEnc = userlib.SymEnc(userSymmKey, userlib.RandomBytes(16), dsPrivKeyBytes)

	contents, err := userlib.Marshal(passwordDataStore)
	if err != nil {
		return nil, err
	}

	sig, err := userlib.DSSign(userdata.DSPrivSignKey, contents)
	if err != nil {
		return nil, err
	}
	passwordDataStoreFinal.UserSignature = sig

	passwordDataStoreBytes, err := userlib.Marshal(passwordDataStoreFinal)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(usernameUUID, passwordDataStoreBytes)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {

	// Check for UUID(username) in datastore. If it's not there, raise DNE error. Then, check if the digital signature of the password is valid. If not,
	// raise "integrity has been compromised" error, else continue. Now, check if valid credentials: take password given and put it
	// through salting process hash(password+saltHash(username)) and see if it's equal to the value for the UUID key. If it's not, raise
	// "invalid credentials" error, else return a userdataptr to the user struct
	var userdata User
	userdata.Username = username
	usernameUUIDBytes, _ := userlib.Marshal("Username:" + username)
	usernameUUID, err := userlib.UUIDFromBytes(userlib.Hash(usernameUUIDBytes))
	if err != nil {
		return nil, err
	}
	var ok bool
	userdata.DSPubVerifyKey, ok = userlib.KeystoreGet(username + "DSPubVerifyKey")
	if !ok {
		return nil, errors.New("DNE")
	}
	userdata.PKEPubEncKey, ok = userlib.KeystoreGet(username + "PKEPubEncKey")

	passwordDataStoreOuterBytes, ok := userlib.DatastoreGet(usernameUUID)
	// If user's data doesn't exist when it should
	if !ok {
		return nil, errors.New("Integrity of userdata has been compromised")
	}
	var passwordDataStoreOuter UserDatastoreOuter
	err = userlib.Unmarshal(passwordDataStoreOuterBytes, &passwordDataStoreOuter)
	// If user's data doesn't unmarshal correctly when it should
	if err != nil {
		return nil, errors.New("Integrity of userdata has been compromised")
	}
	msgBytes, err := userlib.Marshal(*(passwordDataStoreOuter.UserDatastore))
	sigBytes := passwordDataStoreOuter.UserSignature
	err = userlib.DSVerify(userdata.DSPubVerifyKey, msgBytes, sigBytes)
	// If user's data doesn't verify data signature
	if err != nil {
		return nil, errors.New("Integrity of userdata has been compromised")
	}
	userdata.Salt = passwordDataStoreOuter.Salt

	passwordBytes, err := userlib.Marshal(password)
	if err != nil {
		return nil, err
	}
	saltedPassword := userlib.Argon2Key(passwordBytes, userdata.Salt, 128)
	if len(saltedPassword) != len(passwordDataStoreOuter.PasswordHash) {
		return nil, errors.New("Incorrect password submitted")
	}
	for i, v := range saltedPassword {
		if v != passwordDataStoreOuter.PasswordHash[i] {
			return nil, errors.New("Incorrect password submitted")
		}
	}

	userSymmKey := userlib.Argon2Key(passwordBytes, passwordDataStoreOuter.SymmKeySalt, 16)

	pkePrivKeyEncBytes := passwordDataStoreOuter.PKEPrivKeyEnc
	err = userlib.Unmarshal(userlib.SymDec(userSymmKey, pkePrivKeyEncBytes), &(userdata.PKEPrivDecKey))

	dsPrivKeyEncBytes := passwordDataStoreOuter.DSPrivKeyEnc
	err = userlib.Unmarshal(userlib.SymDec(userSymmKey, dsPrivKeyEncBytes), &(userdata.DSPrivSignKey))

	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	//Gets mailboxPtr and keys, and verifies integrity along the way
	mailboxPtr, mailboxUUID, mailboxKey, mailboxMACKey, err := userdata.checkIfFileExistsForUser(filename)
	// If datastore errored at some point while searching for an existing file, return error.
	if err != nil {
		return err
	}
	// This means the file already exists for this user's namespace
	if mailboxPtr != nil {
		var fileLocation userlib.UUID
		err = userlib.Unmarshal(userlib.SymDec(mailboxKey, mailboxPtr.LocationFileEnc), &fileLocation)
		if err != nil {
			return errors.New("Unmarshal Failed!")
		}
		var oldFileLength int
		err = userlib.Unmarshal(userlib.SymDec(mailboxKey, mailboxPtr.FileLength), &oldFileLength)
		if err != nil {
			return errors.New("Unmarshal of File Length Failed!")
		}
		// Use mailbox to find file and get keys. Also overwrite old file length, and set datastore to new mailbox.
		fileKey := userlib.SymDec(mailboxKey, mailboxPtr.PrivKeyFileEnc)
		fileMACKey := userlib.SymDec(mailboxKey, mailboxPtr.MACKeyFileEnc)
		newFileLenBytes, _ := userlib.Marshal(len(content))
		mailboxPtr.FileLength = userlib.SymEnc(mailboxKey, userlib.RandomBytes(16), newFileLenBytes)
		mailboxBytes, _ := userlib.Marshal(*(mailboxPtr.Mailbox))
		mailboxPtr.MAC_Tag, _ = userlib.HMACEval(mailboxMACKey, mailboxBytes)
		mailboxOuterMarshal, _ := userlib.Marshal((*mailboxPtr))
		userlib.DatastoreSet(mailboxUUID, mailboxOuterMarshal)

		firstBlockLocBytes, _ := userlib.Marshal(fileLocation.String() + strconv.Itoa(0))
		firstBlockLoc, _ := userlib.UUIDFromBytes(userlib.Hash(firstBlockLocBytes))
		_, ok := userlib.DatastoreGet(firstBlockLoc)
		if !ok {
			return errors.New(strings.ToTitle("Integrity Compromised! No file at expected location!"))
		}

		// Iterates through file blocks, overwriting whatever exists or doesn't at those blocks
		for i := 0; i < len(content); i += FILE_BLOCK_SIZE {
			var file File
			if FILE_BLOCK_SIZE >= (len(content) - i) {
				file.MAC_Tag, file.Ciphertext, _ = encryptThenMAC(fileKey, userlib.RandomBytes(16), content[i:], fileMACKey)
			} else {
				file.MAC_Tag, file.Ciphertext, _ = encryptThenMAC(fileKey, userlib.RandomBytes(16), content[i:(i+FILE_BLOCK_SIZE)], fileMACKey)
			}
			currBlockLocBytes, _ := userlib.Marshal(fileLocation.String() + strconv.Itoa(i/FILE_BLOCK_SIZE))
			currBlockLoc, _ := userlib.UUIDFromBytes(userlib.Hash(currBlockLocBytes))
			dataStoreBytes, err := userlib.Marshal(file)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(currBlockLoc, dataStoreBytes)
		}
		/*
			// This iteration cleans up extra blocks from an old larger file.
			if (oldFileLength-1)/FILE_BLOCK_SIZE > (len(content)-1)/FILE_BLOCK_SIZE {
				for i := ((oldFileLength - 1) / FILE_BLOCK_SIZE) * FILE_BLOCK_SIZE; i < oldFileLength; i += FILE_BLOCK_SIZE {
					currBlockLocBytes, _ := userlib.Marshal(fileLocation.String() + strconv.Itoa(i/FILE_BLOCK_SIZE))
					currBlockLoc, _ := userlib.UUIDFromBytes(userlib.Hash(currBlockLocBytes))
					userlib.DatastoreDelete(currBlockLoc)
				}
			}
		*/
		return nil
	}
	//File does not exist for this user's namespace if this code runs
	// Encrypt and MAC the new file and put it in the Datastore
	privKeyFile := userlib.RandomBytes(16)
	MACKeyFile := userlib.RandomBytes(16)
	LocationFile := userlib.UUIDNew()

	for i := 0; i < len(content); i += FILE_BLOCK_SIZE {
		var file File
		if (FILE_BLOCK_SIZE) >= (len(content) - i) {
			file.MAC_Tag, file.Ciphertext, _ = encryptThenMAC(privKeyFile, userlib.RandomBytes(16), content[i:], MACKeyFile)
		} else {
			file.MAC_Tag, file.Ciphertext, _ = encryptThenMAC(privKeyFile, userlib.RandomBytes(16), content[i:(i+FILE_BLOCK_SIZE)], MACKeyFile)
		}
		currBlockLocBytes, _ := userlib.Marshal(LocationFile.String() + strconv.Itoa(i/FILE_BLOCK_SIZE))
		currBlockLoc, _ := userlib.UUIDFromBytes(userlib.Hash(currBlockLocBytes))
		dataStoreBytes, err := userlib.Marshal(file)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(currBlockLoc, dataStoreBytes)
	}

	// Encrypt, MAC, and Marshall the Mailbox and put it in the Datastore
	var mailboxOuter MailboxOuter
	var mailbox Mailbox
	mailboxOuter.Mailbox = &mailbox
	privKeyMailbox := userlib.RandomBytes(16)

	LocationMailbox := userlib.UUIDNew()
	LocationFileBytes, _ := userlib.Marshal(LocationFile)
	fileLenBytes, _ := userlib.Marshal(len(content))
	mailbox.FileLength = userlib.SymEnc(privKeyMailbox, userlib.RandomBytes(16), fileLenBytes)
	mailbox.LocationFileEnc = userlib.SymEnc(privKeyMailbox, userlib.RandomBytes(16), LocationFileBytes)
	mailbox.PrivKeyFileEnc = userlib.SymEnc(privKeyMailbox, userlib.RandomBytes(16), privKeyFile)
	MACKeyMailbox := userlib.RandomBytes(16)
	mailbox.MACKeyFileEnc = userlib.SymEnc(privKeyMailbox, userlib.RandomBytes(16), MACKeyFile)

	mailboxBytes, err := userlib.Marshal(mailbox)
	mailboxOuter.MAC_Tag, _ = userlib.HMACEval(MACKeyMailbox, mailboxBytes)
	mailboxOuterBytes, _ := userlib.Marshal(mailboxOuter)
	userlib.DatastoreSet(LocationMailbox, mailboxOuterBytes)

	// Make a new user file node, then Encrypt, DS, and Marshall it and put it in the Datastore
	var userNode UserFileNode
	var userNodeData UserFileNodeData
	userNodeData.Username = userdata.Username
	LocMailboxBytes, _ := userlib.Marshal(LocationMailbox)
	userNodeData.LocationMailbox, _ = userlib.PKEEnc(userdata.PKEPubEncKey, LocMailboxBytes)
	userNodeData.PrivKeyMailbox, _ = userlib.PKEEnc(userdata.PKEPubEncKey, privKeyMailbox)
	userNodeData.MACKeyMailbox, _ = userlib.PKEEnc(userdata.PKEPubEncKey, MACKeyMailbox)
	userNodeData.Children = []userlib.UUID{}

	MACKeyNodesPlain := userlib.RandomBytes(16)
	userNodeData.MACKeyNodes, _ = userlib.PKEEnc(userdata.PKEPubEncKey, MACKeyNodesPlain)

	userNode.UserFileNodeData = &userNodeData

	userNodeDataBytes, _ := userlib.Marshal(userNodeData)
	userNode.MAC_Tag, err = userlib.HMACEval(MACKeyNodesPlain, userNodeDataBytes)

	userFileNodeLocBytes, _ := userlib.Marshal(userdata.Username + "File:" + filename)
	LocationUserNode, _ := userlib.UUIDFromBytes(userlib.Hash(userFileNodeLocBytes))
	marshalledUserNode, _ := userlib.Marshal(userNode)
	userlib.DatastoreSet(LocationUserNode, marshalledUserNode)

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	mailboxPtr, mailBoxLocation, mailboxSymmKey, mailboxMACKey, err := userdata.checkIfFileExistsForUser(filename)
	if err != nil {
		return err
	}
	// This means file doesn't exist for this user's namespace
	if mailboxPtr == nil {
		return errors.New("File either does not exist for this user or the UserFileNode was maliciously removed")
	}
	if len(content) == 0 {
		return nil
	}
	var FileLocation userlib.UUID
	err = userlib.Unmarshal(userlib.SymDec(mailboxSymmKey, mailboxPtr.LocationFileEnc), &FileLocation)
	if err != nil {
		return errors.New("Mailbox did not unmarshal correctly!")
	}

	var oldFileLength int
	err = userlib.Unmarshal(userlib.SymDec(mailboxSymmKey, mailboxPtr.FileLength), &oldFileLength)
	if err != nil {
		return errors.New("File Length did not Unmarshal correctly!")
	}

	newFileLength := oldFileLength + len(content)

	// Use mailbox to find file and get keys. Also overwrite old file length, and set datastore to new mailbox.
	fileKey := userlib.SymDec(mailboxSymmKey, mailboxPtr.PrivKeyFileEnc)
	fileMACKey := userlib.SymDec(mailboxSymmKey, mailboxPtr.MACKeyFileEnc)
	newFileLenBytes, _ := userlib.Marshal(newFileLength)
	mailboxPtr.FileLength = userlib.SymEnc(mailboxSymmKey, userlib.RandomBytes(16), newFileLenBytes)
	mailboxBytes, _ := userlib.Marshal(*(mailboxPtr.Mailbox))
	mailboxPtr.MAC_Tag, _ = userlib.HMACEval(mailboxMACKey, mailboxBytes)
	mailboxOuterMarshal, _ := userlib.Marshal((*mailboxPtr))
	userlib.DatastoreSet(mailBoxLocation, mailboxOuterMarshal)

	// append to last block
	var contentIndex int
	if oldFileLength%FILE_BLOCK_SIZE != 0 {
		lastBlockLocBytes, _ := userlib.Marshal(FileLocation.String() + strconv.Itoa(oldFileLength/FILE_BLOCK_SIZE))
		lastBlockLoc, _ := userlib.UUIDFromBytes(userlib.Hash(lastBlockLocBytes))
		marshalledBlock, ok := userlib.DatastoreGet(lastBlockLoc)
		if !ok {
			return errors.New(strings.ToTitle("File Block not found when expected! Data Integrity violated."))
		}
		var fileBlock File
		err = userlib.Unmarshal(marshalledBlock, &fileBlock)
		if err != nil {
			return err
		}
		oldMAC := fileBlock.MAC_Tag
		newMAC, _ := userlib.HMACEval(fileMACKey, fileBlock.Ciphertext)
		if !userlib.HMACEqual(oldMAC, newMAC) {
			return errors.New("File Block integrity compromised!")
		}
		oldPlainText := userlib.SymDec(fileKey, fileBlock.Ciphertext)
		var newPlainText []byte

		if (FILE_BLOCK_SIZE - len(oldPlainText)) >= len(content) {
			newPlainText = append(oldPlainText, content[0:]...)
			contentIndex = len(content)
		} else {
			newPlainText = append(oldPlainText, content[0:FILE_BLOCK_SIZE-len(oldPlainText)]...)
			contentIndex = FILE_BLOCK_SIZE - len(oldPlainText)
		}
		fileBlock.Ciphertext = userlib.SymEnc(fileKey, userlib.RandomBytes(16), newPlainText)
		fileBlock.MAC_Tag, _ = userlib.HMACEval(fileMACKey, fileBlock.Ciphertext)
		dataStoreBytes, _ := userlib.Marshal(fileBlock)
		userlib.DatastoreSet(lastBlockLoc, dataStoreBytes)
	}
	var startInd int
	if oldFileLength%FILE_BLOCK_SIZE == 0 {
		startInd = (oldFileLength / FILE_BLOCK_SIZE) * FILE_BLOCK_SIZE
	} else {
		startInd = ((oldFileLength + FILE_BLOCK_SIZE) / FILE_BLOCK_SIZE) * FILE_BLOCK_SIZE
	}
	//Set to oldFileLength / 128 * 128 if oldFileLength % 128 == 0, set to that plus 1 otherwise
	for i := startInd; i < newFileLength; i += FILE_BLOCK_SIZE {
		var currBlockLocBytes []byte
		currBlockLocBytes, _ = userlib.Marshal(FileLocation.String() + strconv.Itoa(i/FILE_BLOCK_SIZE))
		currBlockLoc, _ := userlib.UUIDFromBytes(userlib.Hash(currBlockLocBytes))

		var fileBlock File
		if contentIndex+FILE_BLOCK_SIZE >= (len(content)) {
			fileBlock.MAC_Tag, fileBlock.Ciphertext, _ = encryptThenMAC(fileKey, userlib.RandomBytes(16),
				content[contentIndex:], fileMACKey)
			contentIndex = len(content)
		} else {
			fileBlock.MAC_Tag, fileBlock.Ciphertext, _ = encryptThenMAC(fileKey, userlib.RandomBytes(16),
				content[contentIndex:contentIndex+FILE_BLOCK_SIZE], fileMACKey)
			contentIndex = contentIndex + FILE_BLOCK_SIZE
		}
		dataStoreBytes, err := userlib.Marshal(fileBlock)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(currBlockLoc, dataStoreBytes)

	}
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {

	// Get user node
	userFileNodeLocBytes, _ := userlib.Marshal(userdata.Username + "File:" + filename)
	LocationUserNode, _ := userlib.UUIDFromBytes(userlib.Hash(userFileNodeLocBytes))
	marshalledUserNode, ok := userlib.DatastoreGet(LocationUserNode)
	if !ok {
		return nil, errors.New(strings.ToTitle("File with user not found!"))
	}
	var userNode UserFileNode
	userlib.Unmarshal(marshalledUserNode, &userNode)
	// Check User File node MAC, if good contnue.
	oldMACNode := userNode.MAC_Tag
	decryptedMACKey, _ := userlib.PKEDec(userdata.PKEPrivDecKey, userNode.MACKeyNodes)
	userNodeInnerBytes, _ := userlib.Marshal(*(userNode.UserFileNodeData))
	newMACNode, _ := userlib.HMACEval(decryptedMACKey, userNodeInnerBytes)
	if !userlib.HMACEqual(oldMACNode, newMACNode) {
		return nil, errors.New("LoadFile - UserFileNode data corrupted!")
	}

	// Use location of mailbox to get mailbox. Unmarshal.
	mailboxLocationBytes, _ := userlib.PKEDec(userdata.PKEPrivDecKey, userNode.LocationMailbox)
	var mailboxLocationPlain userlib.UUID
	err = userlib.Unmarshal(mailboxLocationBytes, &mailboxLocationPlain)
	marshalledMailbox, ok := userlib.DatastoreGet(mailboxLocationPlain)
	if !ok {
		return nil, errors.New(strings.ToTitle("Mailbox for file not found!"))
	}
	var mailboxOuter MailboxOuter
	userlib.Unmarshal(marshalledMailbox, &mailboxOuter)
	// Decrypt then Unmarshall Mailbox inner

	// Check mailbox MAC, if good continue, if bad throw error. Also, decrypt Priv and MAC keys.

	decryptedMACKeyMailbox, _ := userlib.PKEDec(userdata.PKEPrivDecKey, userNode.MACKeyMailbox)
	decryptedPrivKeyMailbox, _ := userlib.PKEDec(userdata.PKEPrivDecKey, userNode.PrivKeyMailbox)

	oldMAC := mailboxOuter.MAC_Tag
	mailboxInnerBytes, _ := userlib.Marshal(*(mailboxOuter.Mailbox))
	newMAC, _ := userlib.HMACEval(decryptedMACKeyMailbox, mailboxInnerBytes)
	if !userlib.HMACEqual(oldMAC, newMAC) {
		return nil, errors.New(strings.ToTitle("Mailbox has been tampered with!"))
	}

	var FileLocation userlib.UUID
	err = userlib.Unmarshal(userlib.SymDec(decryptedPrivKeyMailbox, mailboxOuter.LocationFileEnc), &FileLocation)
	var FileLength int
	err = userlib.Unmarshal(userlib.SymDec(decryptedPrivKeyMailbox, mailboxOuter.FileLength), &FileLength)
	if err != nil {
		return nil, err
	}
	FileSymmKey := userlib.SymDec(decryptedPrivKeyMailbox, mailboxOuter.PrivKeyFileEnc)
	FileMACKey := userlib.SymDec(decryptedPrivKeyMailbox, mailboxOuter.MACKeyFileEnc)

	decryptedFile := []byte{}
	for i := 0; i < FileLength; i += FILE_BLOCK_SIZE {
		currBlockLocBytes, _ := userlib.Marshal(FileLocation.String() + strconv.Itoa(i/FILE_BLOCK_SIZE))
		currBlockLoc, _ := userlib.UUIDFromBytes(userlib.Hash(currBlockLocBytes))
		marshalledBlock, ok := userlib.DatastoreGet(currBlockLoc)
		if !ok {
			return nil, errors.New(strings.ToTitle("File not found when expected! Data Integrity violated." + FileLocation.String() + strconv.Itoa(i/FILE_BLOCK_SIZE)))
		}
		var fileBlock File
		err = userlib.Unmarshal(marshalledBlock, &fileBlock)
		if err != nil {
			return nil, err
		}
		oldMAC := fileBlock.MAC_Tag
		newMAC, _ := userlib.HMACEval(FileMACKey, fileBlock.Ciphertext)
		if !userlib.HMACEqual(oldMAC, newMAC) {
			return nil, errors.New("File integrity compromised!")
		}
		decryptedFile = append(decryptedFile, userlib.SymDec(FileSymmKey, fileBlock.Ciphertext)...)
	}
	// Return file
	return decryptedFile, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr userlib.UUID, err error) {
	bobPKEPubKey, ok := userlib.KeystoreGet(recipientUsername + "PKEPubEncKey")
	if !ok {
		return userlib.UUIDNew(), errors.New("Recipient does not exist!")
	}
	if userdata.Username == recipientUsername {
		return userlib.UUIDNew(), errors.New("Cannot invite yourself!")
	}
	// Pull Alice's file node up to get information needed to populate Bob's invitation
	userFileNodeLocBytes, _ := userlib.Marshal(userdata.Username + "File:" + filename)
	LocationUserNode, _ := userlib.UUIDFromBytes(userlib.Hash(userFileNodeLocBytes))
	marshalledUserNode, ok := userlib.DatastoreGet(LocationUserNode)
	if !ok {
		return userlib.UUIDNew(), errors.New(strings.ToTitle("File in user's namespace not found!"))
	}
	var aliceUserFileNode UserFileNode
	userlib.Unmarshal(marshalledUserNode, &aliceUserFileNode)
	// Check Alice's file node MAC, if good contnue.
	oldMACNode := aliceUserFileNode.MAC_Tag
	MACKeyNodesDec, _ := userlib.PKEDec(userdata.PKEPrivDecKey, aliceUserFileNode.MACKeyNodes)
	userNodeInnerBytes, _ := userlib.Marshal(*(aliceUserFileNode.UserFileNodeData))
	newMACNode, _ := userlib.HMACEval(MACKeyNodesDec, userNodeInnerBytes)
	if !userlib.HMACEqual(oldMACNode, newMACNode) {
		return userlib.UUIDNew(), errors.New("CreateInv - UserFileNode data corrupted!")
	}
	// Decrypt keys and fields in Alice's userFileNode
	LocationMailboxDec, _ := userlib.PKEDec(userdata.PKEPrivDecKey, aliceUserFileNode.LocationMailbox)
	PrivKeyMailboxDec, _ := userlib.PKEDec(userdata.PKEPrivDecKey, aliceUserFileNode.PrivKeyMailbox)
	MACKeyMailboxDec, _ := userlib.PKEDec(userdata.PKEPrivDecKey, aliceUserFileNode.MACKeyMailbox)

	// Populate Bob's Invitation
	var bobInvitation Invitation
	var bobInvitationData InvitationData
	bobInvitationData.LocationMailbox, _ = userlib.PKEEnc(bobPKEPubKey, LocationMailboxDec)
	bobInvitationData.PrivKeyMailbox, _ = userlib.PKEEnc(bobPKEPubKey, PrivKeyMailboxDec)
	bobInvitationData.MACKeyMailbox, _ = userlib.PKEEnc(bobPKEPubKey, MACKeyMailboxDec)
	bobInvitationData.MACKeyNodes, _ = userlib.PKEEnc(bobPKEPubKey, MACKeyNodesDec)
	LocationUserNodeBytes, _ := userlib.Marshal(LocationUserNode)
	bobInvitationData.ParentLocation, _ = userlib.PKEEnc(bobPKEPubKey, LocationUserNodeBytes)

	bobInvitation.InvitationData = &bobInvitationData

	bobInvitationDataBytes, _ := userlib.Marshal(bobInvitationData)
	bobInvitation.DS_Signature, err = userlib.DSSign(userdata.DSPrivSignKey, bobInvitationDataBytes)

	LocationInvitation := userlib.UUIDNew()
	marshalledInvitation, _ := userlib.Marshal(bobInvitation)
	userlib.DatastoreSet(LocationInvitation, marshalledInvitation)

	return LocationInvitation, nil

}

// Should recieve invitationPtr and only then create the node.
func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr userlib.UUID, filename string) error {
	locBytes, _ := userlib.Marshal(userdata.Username + "File:" + filename)
	loc, _ := userlib.UUIDFromBytes(userlib.Hash(locBytes))
	_, ok := userlib.DatastoreGet(loc)
	if ok {
		return errors.New("File either already exists for this user's namespace, or integrity broken and malicous node added.")
	}
	marshalledInvitation, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("No invitation found at this pointer!")
	}
	var invitation Invitation
	err := userlib.Unmarshal(marshalledInvitation, &invitation)
	if err != nil {
		return errors.New("Unmarshal Failed unexpectedly! Possible data tampering!")
	}
	parentPubVerifyKey, ok := userlib.KeystoreGet(senderUsername + "DSPubVerifyKey")
	if !ok {
		return errors.New("Sender Username doesn't exist")
	}
	invitationDataBytes, _ := userlib.Marshal(invitation.InvitationData)
	err = userlib.DSVerify(parentPubVerifyKey, invitationDataBytes, invitation.DS_Signature)
	if err != nil {
		return errors.New("Digital Signature Failed, file either not sent by senderUsername or tampered with")
	}

	nodesMACKey, _ := userlib.PKEDec(userdata.PKEPrivDecKey, invitation.MACKeyNodes)
	parentUUIDBytes, _ := userlib.PKEDec(userdata.PKEPrivDecKey, invitation.ParentLocation)
	var parentFileNodeUUID userlib.UUID
	err = userlib.Unmarshal(parentUUIDBytes, &parentFileNodeUUID)
	if err != nil {
		return errors.New("Unmarshal Failed unexpectedly! Possible Data tampering!")
	}

	// Get the parents user node from the Datastore, verify its correct with the MAC.
	// Then change add yourself to the children list and generate a new tag.
	parentFileNodeBytes, ok := userlib.DatastoreGet(parentFileNodeUUID)
	if !ok {
		return errors.New("No node at UUID, data either tampered with or parent was revoked!")
	}
	var parentFileNode UserFileNode
	err = userlib.Unmarshal(parentFileNodeBytes, &parentFileNode)
	if err != nil {
		return errors.New("Unmarshal Failed Unexpectedly! Possible Data tampering!")
	}
	oldMAC := parentFileNode.MAC_Tag
	innerNodeBytes, _ := userlib.Marshal(parentFileNode.UserFileNodeData)
	newMAC, _ := userlib.HMACEval(nodesMACKey, innerNodeBytes)
	if !userlib.HMACEqual(oldMAC, newMAC) {
		return errors.New("MACs not equal, parent node posssibly tampered with or invitation revoked!")
	}

	userFileNodeLocBytes, _ := userlib.Marshal(userdata.Username + "File:" + filename)
	LocationUserNode, _ := userlib.UUIDFromBytes(userlib.Hash(userFileNodeLocBytes))
	parentFileNode.Children = append(parentFileNode.Children, LocationUserNode)

	marshalParentNodeInner, _ := userlib.Marshal(*(parentFileNode.UserFileNodeData))
	parentFileNode.MAC_Tag, _ = userlib.HMACEval(nodesMACKey, marshalParentNodeInner)
	marshalledParentNode, _ := userlib.Marshal(parentFileNode)
	userlib.DatastoreSet(parentFileNodeUUID, marshalledParentNode)

	// Make a new user file node, then Encrypt, DS, and Marshall it and put it in the Datastore
	var recipientFileNode UserFileNode
	var recipientFileNodeData UserFileNodeData
	recipientFileNode.UserFileNodeData = &recipientFileNodeData

	recipientFileNode.Username = userdata.Username
	recipientFileNode.LocationMailbox = invitation.LocationMailbox
	recipientFileNode.PrivKeyMailbox = invitation.PrivKeyMailbox
	recipientFileNode.MACKeyMailbox = invitation.MACKeyMailbox
	recipientFileNode.MACKeyNodes = invitation.MACKeyNodes
	recipientFileNode.Children = []userlib.UUID{}

	recipientFileNodeDataBytes, _ := userlib.Marshal(recipientFileNodeData)
	recipientFileNode.MAC_Tag, err = userlib.HMACEval(nodesMACKey, recipientFileNodeDataBytes)

	marshalledUserNode, _ := userlib.Marshal(recipientFileNode)
	userlib.DatastoreSet(LocationUserNode, marshalledUserNode)
	return nil
}

// Go to parent of the removed person and delete revoked's children, revoked Node, and then their UUID from list.
// Then from User (File owner)'s node regenerate the keys and dispense them to all child nodes and file/mailbox.
// Verify as you go along to ensure children lists not tampered with
func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	if userdata.Username == recipientUsername {
		return errors.New("Cannot revoke yourself!")
	}
	_, ok := userlib.KeystoreGet(recipientUsername + "PKEPubEncKey")
	if !ok {
		return errors.New("Recipient username does not exist!")
	}
	InvitationLocBytes, _ := userlib.Marshal(recipientUsername + "Invitation:" + filename)
	LocationInvitation, _ := userlib.UUIDFromBytes(userlib.Hash(InvitationLocBytes))
	userlib.DatastoreDelete(LocationInvitation)

	FileOwnerNodeLocBytes, _ := userlib.Marshal(userdata.Username + "File:" + filename)
	FileOwnerNodeLoc, _ := userlib.UUIDFromBytes(userlib.Hash(FileOwnerNodeLocBytes))
	FileOwnerNodeBytes, ok := userlib.DatastoreGet(FileOwnerNodeLoc)
	if !ok {
		return errors.New("Integrity violated, fileOwnerNode should exist")
	}
	var FileOwnerNode UserFileNode
	err := userlib.Unmarshal(FileOwnerNodeBytes, &FileOwnerNode)
	if err != nil {
		return err
	}
	FileOwnerNodeInner, _ := userlib.Marshal(*(FileOwnerNode.UserFileNodeData))
	MACKeyNodesPlain, _ := userlib.PKEDec(userdata.PKEPrivDecKey, FileOwnerNode.MACKeyNodes)
	oldMAC := FileOwnerNode.MAC_Tag
	newMAC, _ := userlib.HMACEval(MACKeyNodesPlain, FileOwnerNodeInner)
	if !userlib.HMACEqual(oldMAC, newMAC) {
		return errors.New("Integrity Violated for file owner's node")
	}

	// Get the mailbox Info and verify MAC address
	mailboxLocationBytes, _ := userlib.PKEDec(userdata.PKEPrivDecKey, FileOwnerNode.LocationMailbox)
	var mailboxLocationPlain userlib.UUID
	err = userlib.Unmarshal(mailboxLocationBytes, &mailboxLocationPlain)
	if err != nil {
		return err
	}
	mailboxSymmKeyPlain, _ := userlib.PKEDec(userdata.PKEPrivDecKey, FileOwnerNode.PrivKeyMailbox)
	mailboxMACKeyPlain, _ := userlib.PKEDec(userdata.PKEPrivDecKey, FileOwnerNode.MACKeyMailbox)

	var FileMailboxOuter MailboxOuter
	mailboxBytes, ok := userlib.DatastoreGet(mailboxLocationPlain)
	if !ok {
		return errors.New("Integrity violated, mailbox doesn't exist when it should!")
	}
	err = userlib.Unmarshal(mailboxBytes, &FileMailboxOuter)
	if err != nil {
		return err
	}
	mailboxInnerBytes, _ := userlib.Marshal(*(FileMailboxOuter.Mailbox))
	oldMAC = FileMailboxOuter.MAC_Tag
	newMAC, _ = userlib.HMACEval(mailboxMACKeyPlain, mailboxInnerBytes)
	if !userlib.HMACEqual(oldMAC, newMAC) {
		return errors.New("Integrity Violated for mailbox")
	}
	// Decrypt necessary information for file from mailbox
	var fileLengthPlain int
	err = userlib.Unmarshal(userlib.SymDec(mailboxSymmKeyPlain, FileMailboxOuter.FileLength), &fileLengthPlain)
	if err != nil {
		return err
	}
	var fileLocation userlib.UUID
	err = userlib.Unmarshal(userlib.SymDec(mailboxSymmKeyPlain, FileMailboxOuter.LocationFileEnc), &fileLocation)
	if err != nil {
		return err
	}
	fileSymmKeyPlain := userlib.SymDec(mailboxSymmKeyPlain, FileMailboxOuter.PrivKeyFileEnc)
	fileMACKeyPlain := userlib.SymDec(mailboxSymmKeyPlain, FileMailboxOuter.MACKeyFileEnc)

	// Generate a new File Symm Key and MAC Key, then decrypt and re-encrypt each block, then recalculate new MAC_Tags.
	newFileSymmKeyPlain := userlib.RandomBytes(16)
	newFileMACKeyPlain := userlib.RandomBytes(16)
	newFileLocation := userlib.UUIDNew()

	revokedUserFound := false
	for i := 0; i < fileLengthPlain; i += FILE_BLOCK_SIZE {
		// Get old block and verify integrity
		oldcurrBlockLocBytes, _ := userlib.Marshal(fileLocation.String() + strconv.Itoa(i/FILE_BLOCK_SIZE))
		oldCurrBlockLoc, _ := userlib.UUIDFromBytes(userlib.Hash(oldcurrBlockLocBytes))
		var oldFileBlock File
		oldFileBlockBytes, ok := userlib.DatastoreGet(oldCurrBlockLoc)
		if !ok {
			return errors.New("File block missing! Integrity compromised!")
		}
		err = userlib.Unmarshal(oldFileBlockBytes, &oldFileBlock)
		if err != nil {
			return errors.New("Unmarshal failed! Integrity compromised!")
		}
		oldMAC := oldFileBlock.MAC_Tag
		newMAC, _ := userlib.HMACEval(fileMACKeyPlain, oldFileBlock.Ciphertext)
		if !userlib.HMACEqual(oldMAC, newMAC) {
			return errors.New("File Block MAC Tags not equal! Integrity compromised!")
		}
		// Decrypt the content, delete the old block, then set the new block
		contentBlockPlain := userlib.SymDec(fileSymmKeyPlain, oldFileBlock.Ciphertext)
		userlib.DatastoreDelete(oldCurrBlockLoc)
		var newFileBlock File
		newFileBlock.MAC_Tag, newFileBlock.Ciphertext, _ = encryptThenMAC(newFileSymmKeyPlain, userlib.RandomBytes(16),
			contentBlockPlain, newFileMACKeyPlain)
		currBlockLocBytes, _ := userlib.Marshal(newFileLocation.String() + strconv.Itoa(i/FILE_BLOCK_SIZE))
		currBlockLoc, _ := userlib.UUIDFromBytes(userlib.Hash(currBlockLocBytes))
		dataStoreBytes, err := userlib.Marshal(newFileBlock)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(currBlockLoc, dataStoreBytes)
	}
	// Generate new mailbox keys, set mailbox fields to new values. Generate new UUID for mailbox and delete the old one.
	newMailboxSymmKey := userlib.RandomBytes(16)
	newMailboxMACKey := userlib.RandomBytes(16)
	newMailboxLocation := userlib.UUIDNew()

	newFileLocationBytes, _ := userlib.Marshal(newFileLocation)
	FileMailboxOuter.LocationFileEnc = userlib.SymEnc(newMailboxSymmKey, userlib.RandomBytes(16), newFileLocationBytes)
	FileMailboxOuter.PrivKeyFileEnc = userlib.SymEnc(newMailboxSymmKey, userlib.RandomBytes(16), newFileSymmKeyPlain)
	FileMailboxOuter.MACKeyFileEnc = userlib.SymEnc(newMailboxSymmKey, userlib.RandomBytes(16), newFileMACKeyPlain)
	fileLengthBytes, _ := userlib.Marshal(fileLengthPlain)
	FileMailboxOuter.FileLength = userlib.SymEnc(newMailboxSymmKey, userlib.RandomBytes(16), fileLengthBytes)
	mailboxInnerBytes, _ = userlib.Marshal(*(FileMailboxOuter.Mailbox))
	FileMailboxOuter.MAC_Tag, _ = userlib.HMACEval(newMailboxMACKey, mailboxInnerBytes)
	userlib.DatastoreDelete(mailboxLocationPlain)
	FileMailboxOuterBytes, _ := userlib.Marshal(FileMailboxOuter)
	userlib.DatastoreSet(newMailboxLocation, FileMailboxOuterBytes)

	newMACKeyNodes := userlib.RandomBytes(16)
	newMailboxLocationBytes, _ := userlib.Marshal(newMailboxLocation)

	// DFS the Tree, MAC as we go along at children level.
	// When you find the revoked user, delete it and all its children.
	stack := []userlib.UUID{FileOwnerNodeLoc}
	for len(stack) != 0 {
		currUUID := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		currNodeMarshalled, ok := userlib.DatastoreGet(currUUID)
		if !ok {
			return errors.New("Expected node at this UUID, possible tampering involved")
		}
		var currNode UserFileNode
		err := userlib.Unmarshal(currNodeMarshalled, &currNode)
		if err != nil {
			return errors.New("Unmarshal failed at expected UUID, possible tampering involved")
		}
		childIndexToRemove := -1
		for i := 0; i < len(currNode.Children); i += 1 {
			childNodeMarshalled, ok := userlib.DatastoreGet(currNode.Children[i])
			if !ok {
				return errors.New("Expected node at this UUID, possible tampering involved")
			}
			var childNode UserFileNode
			err := userlib.Unmarshal(childNodeMarshalled, &childNode)
			if err != nil {
				return errors.New("Unmarshal failed at expected UUID, possible tampering involved")
			}
			childNodeInner, _ := userlib.Marshal(*(childNode.UserFileNodeData))
			oldMAC := childNode.MAC_Tag
			newMAC, _ := userlib.HMACEval(MACKeyNodesPlain, childNodeInner)
			if !userlib.HMACEqual(oldMAC, newMAC) {
				return errors.New("Integrity Violated for current node")
			}
			if childNode.Username == recipientUsername {
				deleteNodeAndChildren(&childNode, currNode.Children[i], MACKeyNodesPlain)
				childIndexToRemove = i
				revokedUserFound = true
			} else {
				stack = append(stack, currNode.Children[i])
			}
		}
		if childIndexToRemove != -1 {
			newChildren := []userlib.UUID{}
			for i := 0; i < len(currNode.Children); i += 1 {
				if childIndexToRemove != i {
					newChildren = append(newChildren, currNode.Children[i])
				}
			}
			currNode.Children = newChildren
		}

		// Update currNode and set datastore.
		currUserPKEPubKey, ok := userlib.KeystoreGet(currNode.Username + "PKEPubEncKey")
		if !ok {
			errors.New("Error should never occur! Says user doesn't exist despite already confirming tag of currNode's username!")
		}
		currNode.LocationMailbox, _ = userlib.PKEEnc(currUserPKEPubKey, newMailboxLocationBytes)
		currNode.MACKeyMailbox, _ = userlib.PKEEnc(currUserPKEPubKey, newMailboxMACKey)
		currNode.MACKeyNodes, _ = userlib.PKEEnc(currUserPKEPubKey, newMACKeyNodes)
		currNode.PrivKeyMailbox, _ = userlib.PKEEnc(currUserPKEPubKey, newMailboxSymmKey)
		innerUserNodeBytes, _ := userlib.Marshal(*(currNode.UserFileNodeData))
		currNode.MAC_Tag, _ = userlib.HMACEval(newMACKeyNodes, innerUserNodeBytes)
		newCurrNodeMarshalled, _ := userlib.Marshal(currNode)
		userlib.DatastoreSet(currUUID, newCurrNodeMarshalled)
	}
	if !revokedUserFound {
		return errors.New("Given user did not have access to the file!")
	}
	return nil
}

// Helper Functions ==========================================================================================================

func encryptThenMAC(privKey []byte, nonce []byte, content []byte, MACKey []byte) (tag []byte, ciphertext []byte, invalid error) {
	cipher := userlib.SymEnc(privKey, nonce, content)
	MAC_Tag, err := userlib.HMACEval(MACKey, cipher)
	if err == nil {
		return MAC_Tag, cipher, err
	}
	return nil, nil, err
}

// Will reurn keys and location of file. If given an int instead of -1 it will update the file length of the mailbox and recalculate the MAC_Tag.
func (userdata *User) checkIfFileExistsForUser(filename string) (mailbox *MailboxOuter, mailboxLocation userlib.UUID, mailboxSymmKey []byte, mailboxMACKey []byte, err error) {
	// Get user node
	userFileNodeLocBytes, _ := userlib.Marshal(userdata.Username + "File:" + filename)
	LocationUserNode, _ := userlib.UUIDFromBytes(userlib.Hash(userFileNodeLocBytes))
	marshalledUserNode, ok := userlib.DatastoreGet(LocationUserNode)
	// If the file doesn't already exist, return nil
	if !ok {
		return nil, userlib.UUIDNew(), nil, nil, nil
	}
	var userNode UserFileNode
	err = userlib.Unmarshal(marshalledUserNode, &userNode)
	if err != nil {
		return nil, userlib.UUIDNew(), nil, nil, errors.New("Unmarshal failed, possible data corruption!")
	}
	// Check User File node MAC, if good contnue.
	oldMACNode := userNode.MAC_Tag
	decryptedMACKey, _ := userlib.PKEDec(userdata.PKEPrivDecKey, userNode.MACKeyNodes)
	userNodeInnerBytes, _ := userlib.Marshal(*(userNode.UserFileNodeData))
	newMACNode, _ := userlib.HMACEval(decryptedMACKey, userNodeInnerBytes)
	if !userlib.HMACEqual(oldMACNode, newMACNode) {
		return nil, userlib.UUIDNew(), nil, nil, errors.New("checkIfFileExists - UserFileNode data corrupted!")
	}

	// Use location of mailbox to get mailbox. Unmarshal.
	mailboxLocationBytes, _ := userlib.PKEDec(userdata.PKEPrivDecKey, userNode.LocationMailbox)
	var mailboxLocationPlain userlib.UUID
	err = userlib.Unmarshal(mailboxLocationBytes, &mailboxLocationPlain)
	marshalledMailbox, ok := userlib.DatastoreGet(mailboxLocationPlain)
	if !ok {
		return nil, userlib.UUIDNew(), nil, nil, errors.New(strings.ToTitle("Mailbox for file not found!"))
	}
	var mailboxOuter MailboxOuter
	userlib.Unmarshal(marshalledMailbox, &mailboxOuter)
	// Decrypt then Unmarshall Mailbox inner

	// Check mailbox MAC, if good continue, if bad throw error. Also, decrypt Priv and MAC keys.
	decryptedMACKeyMailbox, _ := userlib.PKEDec(userdata.PKEPrivDecKey, userNode.MACKeyMailbox)
	decryptedPrivKeyMailbox, _ := userlib.PKEDec(userdata.PKEPrivDecKey, userNode.PrivKeyMailbox)
	oldMAC := mailboxOuter.MAC_Tag
	mailboxInnerBytes, _ := userlib.Marshal(*(mailboxOuter.Mailbox))
	newMAC, _ := userlib.HMACEval(decryptedMACKeyMailbox, mailboxInnerBytes)
	if !userlib.HMACEqual(oldMAC, newMAC) {
		return nil, userlib.UUIDNew(), nil, nil, errors.New(strings.ToTitle("Mailbox has been tampered with!"))
	}

	return &mailboxOuter, mailboxLocationPlain, decryptedPrivKeyMailbox, decryptedMACKeyMailbox, nil
}

// currentNode Passed in already legit
func deleteNodeAndChildren(currentNode *UserFileNode, currentNodeLoc userlib.UUID, MACKeyNodes []byte) (err error) {
	for i := 0; i < len(currentNode.Children); i += 1 {
		childNodeMarshalled, ok := userlib.DatastoreGet(currentNode.Children[i])
		if !ok {
			return errors.New("Expected node at this UUID, possible tampering involved")
		}
		var childNode UserFileNode
		err := userlib.Unmarshal(childNodeMarshalled, &childNode)
		if err != nil {
			return errors.New("Unmarshal failed at expected UUID, possible tampering involved")
		}
		childNodeInner, _ := userlib.Marshal(*(childNode.UserFileNodeData))
		oldMAC := childNode.MAC_Tag
		newMAC, _ := userlib.HMACEval(MACKeyNodes, childNodeInner)
		if !userlib.HMACEqual(oldMAC, newMAC) {
			return errors.New("Integrity Violated for current node")
		}
		err = deleteNodeAndChildren(&childNode, currentNode.Children[i], MACKeyNodes)
		if err != nil {
			return err
		}
	}
	userlib.DatastoreDelete(currentNodeLoc)
	return nil
}
