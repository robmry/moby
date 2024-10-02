package opts

import (
	"encoding/json"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestHostGateway(t *testing.T) {
	testcases := []struct {
		name   string
		input  []string
		expStr string
		expErr string
	}{
		{
			name:   "ipv4",
			input:  []string{"10.1.1.1"},
			expStr: "10.1.1.1",
		},
		{
			name:   "ipv6",
			input:  []string{"fdb8:3037:2cb2::1"},
			expStr: "fdb8:3037:2cb2::1",
		},
		{
			name:   "ipv6 and ipv4",
			input:  []string{"fdb8:3037:2cb2::1", "10.1.1.1"},
			expStr: "10.1.1.1,fdb8:3037:2cb2::1",
		},
		{
			name:   "not an address",
			input:  []string{"blah"},
			expErr: `invalid IP address "blah" in option host-gateway-ip`,
		},
		{
			name:   "empty address",
			input:  []string{""},
			expErr: `invalid IP address "" in option host-gateway-ip`,
		},
		{
			name:   "no address",
			input:  []string{},
			expStr: "",
		},
		{
			name:   "two ipv4",
			input:  []string{"10.1.1.1", "10.1.1.2"},
			expErr: "at most one IPv4 address is allowed in option host-gateway-ip",
		},
		{
			name:   "two ipv6",
			input:  []string{"fdb8:3037:2cb2::1", "fdb8:3037:2cb2::2"},
			expErr: "at most one IPv6 address is allowed in option host-gateway-ip",
		},
	}

	for _, tc := range testcases {
		testSetHostGateway(t, tc.name, tc.input, tc.expStr, tc.expErr)

		jsonVal, err := json.Marshal(tc.input)
		assert.NilError(t, err)
		testUnmarshalHostGateway(t, tc.name, jsonVal, tc.expStr, tc.expErr)
	}

	testUnmarshalHostGateway(t, "json object", []byte(`{"addr": "10.1.1.1"}`),
		"", "invalid host-gateway-ip option")
}

func testSetHostGateway(t *testing.T, name string, vals []string, expStr, expErr string) {
	t.Helper()
	var hg HostGateway
	var err error
	for _, val := range vals {
		err = hg.Set(val)
		if err != nil {
			break
		}
	}
	if expErr != "" {
		assert.Check(t, is.Error(err, expErr), "set %s", name)
		return
	}
	assert.Check(t, is.Equal(hg.String(), expStr), "set %s", name)
}

func testUnmarshalHostGateway(t *testing.T, name string, jsonVal []byte, expStr, expErr string) {
	t.Helper()
	var hg HostGateway
	err := hg.UnmarshalJSON([]byte(jsonVal))
	if expErr != "" {
		assert.Check(t, is.ErrorContains(err, expErr), "%s: unmarshal %s", name, jsonVal)
		return
	}
	assert.Check(t, is.Equal(hg.String(), expStr), "%s: unmarshal %s", name, jsonVal)
}
