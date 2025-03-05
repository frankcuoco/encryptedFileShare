# End-to-End Encrypted File Sharing Application

I have made an end-to-end encrypted file sharing service
(similar to Dropbox). The program allows users to create, upload,
& download files from a server, append on to files, be given/revoked
of access from existing files, and invite others to access files.
Users are authenticated with a username and password. This project
utilizes **SHA512 hashes**, **HMACs**, **Public Key Encryption**, **Digital
Signatures**, **Hash-Based Key Derivation**, **Symmetric Encryption**, and
a **Keystore/Datastore**. This application is also resilient to Datastore
and revoked user adversaries. The design, integration, and testing of the
application were all done by me. 
