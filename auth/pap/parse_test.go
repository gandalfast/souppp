package pap

import "testing"

// TestParseRejectsMalformedPackets checks that packets cut short or lying
// about their lengths are rejected with an error rather than a panic.
func TestParseRejectsMalformedPackets(t *testing.T) {
	for _, tc := range []struct {
		name string
		buf  []byte
	}{
		{"request with no peer id length", []byte{1, 1, 0, 6}},
		{"request cut inside the peer id", []byte{1, 1, 0, 10, 4, 'u', 's'}},
		{"request without a password length", []byte{1, 1, 0, 9, 4, 'u', 's', 'e', 'r'}},
		{"request cut inside the password", []byte{1, 1, 0, 14, 4, 'u', 's', 'e', 'r', 4, 'p', 'a'}},
		{"ack with no message length", []byte{2, 1, 0, 4}},
		{"ack cut inside the message", []byte{2, 1, 0, 7, 2, 'o'}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p Packet
			if err := p.Parse(tc.buf); err == nil {
				t.Fatalf("Parse(% x) = nil, want an error", tc.buf)
			}
		})
	}
}

// TestParseRequestAndAck checks well-formed packets parse into their fields.
func TestParseRequestAndAck(t *testing.T) {
	var req Packet
	if err := req.Parse([]byte{1, 1, 0, 14, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'}); err != nil {
		t.Fatal(err)
	}
	if req.Code != CodeAuthRequest || string(req.PeerID) != "user" || string(req.Password) != "pass" {
		t.Fatalf("parsed %+v, want a request for user with password pass", req)
	}
	var ack Packet
	if err := ack.Parse([]byte{2, 1, 0, 7, 2, 'o', 'k'}); err != nil {
		t.Fatal(err)
	}
	if ack.Code != CodeAuthACK || string(ack.Msg) != "ok" {
		t.Fatalf("parsed %+v, want an ack with message ok", ack)
	}
}
