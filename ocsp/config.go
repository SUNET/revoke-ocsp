package ocsp

const (
	CA_CERT        = "ca.pem"
	RESPONDER_CERT = "responder.pem"
	RESPONDER_KEY  = "responder_key.pem"
	PORT           = 8889

	// A certificate signed by CA_CERT, with serial number 1
	TEST_CLIENT_CERT = "test_client.pem"
)
