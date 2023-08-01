package client_test

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports. Normally, you will want to avoid underscore imports
	// unless you know exactly what you are doing. You can read more about
	// underscore imports here: https://golangdocs.com/blank-identifier-in-golang
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect(). You can read more
	// about dot imports here:
	// https://stackoverflow.com/questions/6478962/what-does-the-dot-or-period-in-a-go-import-statement-do
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	// The client implementation is intentionally defined in a different package.
	// This forces us to follow best practice and write tests that only rely on
	// client API that is exported from the client package, and avoid relying on
	// implementation details private to the client package.
	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	// We are using 2 libraries to help us write readable and maintainable tests:
	//
	// (1) Ginkgo, a Behavior Driven Development (BDD) testing framework that
	//             makes it easy to write expressive specs that describe the
	//             behavior of your code in an organized manner; and
	//
	// (2) Gomega, an assertion/matcher library that allows us to write individual
	//             assertion statements in tests that read more like natural
	//             language. For example "Expect(ACTUAL).To(Equal(EXPECTED))".
	//
	// In the Ginko framework, a test case signals failure by calling Ginkgo’s
	// Fail(description string) function. However, we are using the Gomega library
	// to execute our assertion statements. When a Gomega assertion fails, Gomega
	// calls a GomegaFailHandler, which is a function that must be provided using
	// gomega.RegisterFailHandler(). Here, we pass Ginko's Fail() function to
	// Gomega so that Gomega can report failed assertions to the Ginko test
	// framework, which can take the appropriate action when a test fails.
	//
	// This is the sole connection point between Ginkgo and Gomega.
	RegisterFailHandler(Fail)

	RunSpecs(t, "Client Tests")
}

// ================================================
// Here are some optional global variables that can be used throughout the test
// suite to make the tests more readable and maintainable than defining these
// values in each test. You can add more variables here if you want and think
// they will help keep your code clean!
// ================================================
const someFilename = "file1.txt"
const someOtherFilename = "file2.txt"
const nonExistentFilename = "thisFileDoesNotExist.txt"

const aliceUsername = "Alice"
const alicePassword = "AlicePassword"
const bobUsername = "Bob"
const bobPassword = "BobPassword"
const nilufarUsername = "Nilufar"
const nilufarPassword = "NilufarPassword"
const olgaUsername = "Olga"
const olgaPassword = "OlgaPassword"
const marcoUsername = "Marco"
const marcoPassword = "MarcoPassword"

const nonExistentUsername = "NonExistentUser"

var alice *client.User
var bob *client.User
var nilufar *client.User
var olga *client.User
var marco *client.User

var someFileContent []byte
var someShortFileContent []byte
var someLongFileContent []byte

// ================================================
// The top level Describe() contains all tests in
// this test suite in nested Describe() blocks.
// ================================================

var _ = Describe("Client Tests", func() {
	BeforeEach(func() {
		// This top-level BeforeEach will be run before each test.
		//
		// Resets the state of Datastore and Keystore so that tests do not
		// interfere with each other.
		userlib.DatastoreClear()
		userlib.KeystoreClear()

		userlib.SymbolicDebug = true
		userlib.SymbolicVerbose = false
	})

	BeforeEach(func() {
		// This top-level BeforeEach will be run before each test.
		//
		// Byte slices cannot be constant, so this BeforeEach resets the content of
		// each global variable to a predefined value, which allows tests to rely on
		// the expected value of these variables.
		someShortFileContent = []byte("some short file content")
		someFileContent = someShortFileContent
		someLongFileContent = []byte("some LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file content")
	})

	Describe("Creating users", func() {
		It("should not error when creating a new user", func() {
			_, err := client.InitUser("Alice", "password")
			Expect(err).To(BeNil(), "Failed to initialized user Alice.")
		})

		It("should error if a username is already taken by another user", func() {
			_, err := client.InitUser("Alice", "password")
			Expect(err).To(BeNil(), "Failed to initialized user Alice.")

			_, err = client.InitUser("Alice", "password")
			Expect(err).ToNot(BeNil())
		})

		It("should error if a user does not exist with that username", func() {
			_, err := client.InitUser("Alice", "password")
			Expect(err).To(BeNil(), "Failed to initialized user Alice.")

			_, err = client.GetUser("Bob", bobPassword)
			Expect(err).ToNot(BeNil())
		})

		It("should error if user credentials are invalid", func() {
			_, err := client.InitUser("Alice", "password")
			Expect(err).To(BeNil(), "Failed to initialized user Alice.")

			_, err = client.GetUser("Alice", "hehe its the wrong password LOL")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Single user storage", func() {
		var alice *client.User

		BeforeEach(func() {
			// This BeforeEach will run before each test in this Describe block.
			alice, _ = client.InitUser("Alice", "some password")
		})

		It("should upload content without erroring", func() {
			content := []byte("This is a test")
			err := alice.StoreFile("file1", content)
			Expect(err).To(BeNil(), "Failed to upload content to a file", err)
		})

		It("should download the expected content that was previously uploaded", func() {
			uploadedContent := []byte("This is a test")
			alice.StoreFile(someFilename, uploadedContent)
			downloadedContent, _ := alice.LoadFile(someFilename)

			Expect(downloadedContent).To(BeEquivalentTo(uploadedContent),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				uploadedContent)
		})

		It("should error when trying to download a file that does not exist", func() {
			_, err := alice.LoadFile(nonExistentFilename)
			Expect(err).ToNot(BeNil(), "Was able to load a non-existent file without error.")
		})

		//It("should error when trying to download a file that's been malicously modified", func() {
		//	err := alice.StoreFile("foo.txt", []byte("hello world"))
		//	Expect(err).To(BeNil())

		//datastore := userlib.DatastoreGetMap()
		//datastore[invitation] = []byte("gotcha")

		//	_, err = alice.LoadFile("foo.txt")
		//	Expect(err).To(BeNil())
		//})

		It("should overwrite file if storing one that already exists without error", func() {
			uploadedContent := []byte("This is a test")
			alice.StoreFile(someFilename, uploadedContent)
			downloadedContent, _ := alice.LoadFile(someFilename)

			Expect(downloadedContent).To(BeEquivalentTo(uploadedContent),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				uploadedContent)

			newUploadedContent := []byte("This is the second test")
			err := alice.StoreFile(someFilename, newUploadedContent)
			Expect(err).To(BeNil(), "Was unable to call storeFile twice without erroring")
			newDownloadedContent, err := alice.LoadFile(someFilename)
			Expect(err).To(BeNil(), "Was unable to call loadFile on second store without erroring")
			Expect(newDownloadedContent).To(BeEquivalentTo(newUploadedContent),
				"Second call of StoreFile did not overwrite the existing file correctly",
				downloadedContent,
				uploadedContent)

		})

		It("should upload content 0 bytes without erroring", func() {
			content := []byte{}
			err := alice.StoreFile("file1", content)
			Expect(err).To(BeNil(), "Failed to upload content to a file", err)

			downloadedContent, err := alice.LoadFile("file1")
			Expect(err).To(BeNil(), "Failed to download uploaded content to file")
			Expect(downloadedContent).To(BeEquivalentTo(content),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				content)
		})

		It("should upload content 127 bytes without erroring", func() {
			content := make([]byte, 127)
			err := alice.StoreFile("file1", content)
			Expect(err).To(BeNil(), "Failed to upload content to a file", err)

			downloadedContent, err := alice.LoadFile("file1")
			Expect(err).To(BeNil(), "Failed to download uploaded content to file")
			Expect(downloadedContent).To(BeEquivalentTo(content),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				content)
		})

		It("should upload content 128 bytes without erroring", func() {
			content := make([]byte, 128)
			err := alice.StoreFile("file1", content)
			Expect(err).To(BeNil(), "Failed to upload content to a file", err)
			downloadedContent, err := alice.LoadFile("file1")
			Expect(err).To(BeNil(), "Failed to download uploaded content to file")
			Expect(downloadedContent).To(BeEquivalentTo(content),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				content)
		})

		It("should upload content 259 bytes without erroring", func() {
			content := make([]byte, 259)
			err := alice.StoreFile("file1", content)
			Expect(err).To(BeNil(), "Failed to upload content to a file", err)

			downloadedContent, err := alice.LoadFile("file1")
			Expect(err).To(BeNil(), "Failed to download uploaded content to file")
			Expect(downloadedContent).To(BeEquivalentTo(content),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				content)
		})

		It("should overwrite larger content without erroring", func() {
			content := make([]byte, 259)
			err := alice.StoreFile("file1", content)
			Expect(err).To(BeNil(), "Failed to upload content to a file", err)

			downloadedContent, err := alice.LoadFile("file1")
			Expect(err).To(BeNil(), "Failed to download uploaded content to file")
			Expect(downloadedContent).To(BeEquivalentTo(content),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				content)

			content = make([]byte, 129)
			err = alice.StoreFile("file1", content)
			Expect(err).To(BeNil(), "Failed to upload content to a file", err)
			downloadedContent, err = alice.LoadFile("file1")
			Expect(err).To(BeNil(), "Failed to download uploaded content to file")
			Expect(downloadedContent).To(BeEquivalentTo(content),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				content)

		})

		// Append Tests

		It("should download the expected content that was appended", func() {
			uploadedContent := []byte("This is a test")
			alice.StoreFile(someFilename, uploadedContent)
			currContent := uploadedContent
			for i := 0; i < 128; i += 1 {
				appendedContent := []byte(" and this is another test")
				err := alice.AppendToFile(someFilename, appendedContent)
				Expect(err).To(BeNil(), "Failed to append uploaded content to file")
				downloadedContent, err := alice.LoadFile(someFilename)
				Expect(err).To(BeNil(), "Failed to load appended File.")
				currContent = append(currContent, appendedContent...)
				Expect(downloadedContent).To(BeEquivalentTo(currContent),
					"Downloaded content is not the same as uploaded content",
					downloadedContent,
					uploadedContent)
			}
		})

		It("should append to an empty sequence of bytes.", func() {
			uploadedContent := []byte("")
			alice.StoreFile("empty.txt", uploadedContent)
			appendedContent := []byte("Now it's not empty, haha! Whadaya know, knick knack patty whack.")
			alice.AppendToFile("empty.txt", appendedContent)
			downloadedContent, _ := alice.LoadFile("empty.txt")

			Expect(downloadedContent).To(BeEquivalentTo(append(uploadedContent, appendedContent...)),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				uploadedContent)
		})

		It("should error when trying to append to file that does not exist", func() {
			err := alice.AppendToFile(nonExistentFilename, []byte("This is a test"))
			Expect(err).ToNot(BeNil(), "Was able to load a non-existent file without error.")
		})

	})

	Describe("Sharing files", func() {

		BeforeEach(func() {
			// Initialize each user to ensure the variable has the expected value for
			// the tests in this Describe() block.
			alice, _ = client.InitUser(aliceUsername, alicePassword)
			bob, _ = client.InitUser(bobUsername, bobPassword)
			nilufar, _ = client.InitUser(nilufarUsername, nilufarPassword)
			olga, _ = client.InitUser(olgaUsername, olgaPassword)
			marco, _ = client.InitUser(marcoUsername, marcoPassword)
		})

		It("should share a file without erroring", func() {
			alice.StoreFile(someFilename, someShortFileContent)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			downloadedContent, err := bob.LoadFile(someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")
		})

		// CreateInvitation Tests

		It("File name not existing under name should cause an error", func() {
			alice.StoreFile(someOtherFilename, someFileContent)
			_, err := nilufar.CreateInvitation(someOtherFilename, olgaUsername)
			Expect(err).ToNot(BeNil(), "Nilufar cannot invite Olga to acess the file because they don't have access themselves.")
		})

		It("Recipient username not existing should cause an error", func() {
			alice.StoreFile("norecipient.txt", []byte("We ain't got no one to receive this fella"))
			_, err := alice.CreateInvitation("norecipient.txt", "Frank")
			Expect(err).ToNot(BeNil(), "Alice cannot invite Frank to acess the file because their username does not exist.")
		})

		It("Client throws an error when it can't verify the integrity of a file sharing invitation.", func() {
			err := alice.StoreFile("foo.txt", []byte("hello world"))
			Expect(err).To(BeNil())

			invitation, err := alice.CreateInvitation("foo.txt", bobUsername)
			Expect(err).To(BeNil())

			datastore := userlib.DatastoreGetMap()
			datastore[invitation] = []byte("gotcha")

			err = bob.AcceptInvitation(aliceUsername, invitation, "bar.txt")
			Expect(err).ToNot(BeNil())
		})

		It("Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			aliceDesktop := alice
			aliceLaptop, err := client.GetUser(aliceUsername, alicePassword)
			Expect(err).To(BeNil())

			err = aliceDesktop.StoreFile("bitcoin.txt", []byte("Nick loves bitcoin"))
			Expect(err).To(BeNil())

			_, err = aliceLaptop.CreateInvitation("bitcoin.txt", bobUsername)
			Expect(err).To(BeNil())
		})

		// AcceptInvitation Tests

		It("Throws an error when sharee tries to accept filename that they already have in their personal file namespace.", func() {
			err := alice.StoreFile("notunique.txt", []byte("this ain't unique mayne"))
			Expect(err).To(BeNil())

			err = bob.StoreFile("notunique.txt", []byte("this ain't unique maynee"))
			Expect(err).To(BeNil())

			invitation, err := alice.CreateInvitation("notunique.txt", bobUsername)
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation(aliceUsername, invitation, "notunique.txt")
			Expect(err).ToNot(BeNil())
		})

		It("Throws an error when sharer revokes sharee's access before they accept their invitation.", func() {
			err := alice.StoreFile("hahayouthought.txt", []byte("get rekt"))
			Expect(err).To(BeNil())

			invitation, err := alice.CreateInvitation("hahayouthought.txt", bobUsername)
			Expect(err).To(BeNil())

			alice.RevokeAccess("hahayouthought.txt", bobUsername)

			err = bob.AcceptInvitation(aliceUsername, invitation, "hahayouthought.txt")
			Expect(err).ToNot(BeNil())
		})

		It("Edits should be seen by all sharees", func() {
			alice.StoreFile("willbechanged", []byte("This is all I got rn."))
			shareFileInfoPtr, err := alice.CreateInvitation("willbechanged", bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, "willbechangedbob")
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			shareFileInfoPtr, err = bob.CreateInvitation("willbechangedbob", marcoUsername)
			Expect(err).To(BeNil(), "Bob failed to share a file with Marco.")

			err = marco.AcceptInvitation(bobUsername, shareFileInfoPtr, "willbechangedmarco")
			Expect(err).To(BeNil(), "Marco could not receive the file that Bob shared.")

			appendedContent := []byte(" Ay we got more stuff in here now ayyyyy.")
			alice.AppendToFile("willbechanged", appendedContent)
			downloadedContentAlice, _ := alice.LoadFile("willbechanged")
			downloadedContentBob, _ := bob.LoadFile("willbechangedbob")
			downloadedContentMarco, _ := marco.LoadFile("willbechangedmarco")

			Expect(downloadedContentAlice).To(BeEquivalentTo(append([]byte("This is all I got rn."), appendedContent...)),
				"Append failed")

			Expect(downloadedContentAlice).To(BeEquivalentTo(downloadedContentBob),
				"Bob's file is not the same as Alice's file")
			Expect(downloadedContentBob).To(BeEquivalentTo(downloadedContentMarco),
				"Bob's file is not the same as Marco's file")
			Expect(downloadedContentMarco).To(BeEquivalentTo(downloadedContentAlice),
				"Marco's file is not the same as Alice's file")
		})

		// RevokeAccess Tests

		It("Throws an error when a revoked user tries to access a the file it was revoked from.", func() {
			err := alice.StoreFile("sorrybobby.txt", []byte("I don't like you anymore bobby boy >:-(."))
			Expect(err).To(BeNil())

			invitation, err := alice.CreateInvitation("sorrybobby.txt", bobUsername)
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation(aliceUsername, invitation, "noplsdontrevokemyaccessnooo")
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			err = alice.RevokeAccess("sorrybobby.txt", bobUsername)
			Expect(err).To(BeNil())

			_, err = bob.LoadFile("noplsdontrevokemyaccessnooo")
			Expect(err).ToNot(BeNil())
		})

		It("Throws an error when revoker tries to revoke access to filename not in revokee's personal file namespace.", func() {
			err := alice.StoreFile("thisisafile.txt", []byte("yep."))
			Expect(err).To(BeNil())

			invitation, err := alice.CreateInvitation("thisisafile.txt", bobUsername)
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation(aliceUsername, invitation, "thisisafile.txt")
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			err = alice.RevokeAccess("thisisadifferentfile.txt", bobUsername)
			Expect(err).ToNot(BeNil())
		})

		It("Make sure the file revoked is the caller's name of the file, not the callee.", func() {
			err := alice.StoreFile("fire.txt", []byte("hot."))
			Expect(err).To(BeNil())

			invitation, err := alice.CreateInvitation("fire.txt", bobUsername)
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation(aliceUsername, invitation, "ice.txt")
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			err = alice.StoreFile("ice.txt", []byte("cold."))
			Expect(err).To(BeNil())

			invitation, err = alice.CreateInvitation("ice.txt", bobUsername)
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation(aliceUsername, invitation, "fire.txt")
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			err = alice.RevokeAccess("fire.txt", bobUsername)
			Expect(err).To(BeNil())

			_, err = bob.LoadFile("fire.txt")
			Expect(err).To(BeNil())

			_, err = bob.LoadFile("ice.txt")
			Expect(err).ToNot(BeNil())
		})

		It("Throws an error when revoker tries to revoke access to filename not shared with the revokee.", func() {
			err := alice.StoreFile("thisisafilebro.txt", []byte("yep bro bro."))
			Expect(err).To(BeNil())

			err = alice.RevokeAccess("thisisafilebro.txt", bobUsername)
			Expect(err).ToNot(BeNil())
		})

		// TODO: you probably want more test cases for sharing files here
	})

	// TODO: you probably want more Describe() blocks to contain tests related to
	//       logical test groupings other than the ones suggested above
})
