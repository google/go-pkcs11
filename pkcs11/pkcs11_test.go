package pkcs11

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const (
	libSoftHSMPath = "/usr/lib/softhsm/libsofthsm2.so"
	syslogPath     = "/var/log/syslog"
)

func newTestModule(t *testing.T) *Module {
	if _, err := os.Stat(libSoftHSMPath); err != nil {
		// TODO(ericchiang): do an actual lookup of registered PKCS #11 modules.
		t.Skipf("libsofthsm not installed, skipping testing")
	}

	// Open syslog file and seek to end before the tests starts. Anything read
	// after this will have been logged during the test.
	f, err := os.Open(syslogPath)
	if err != nil {
		t.Fatalf("opening syslog file: %v", err)
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		t.Fatalf("seeking to end of file: %v", err)
	}

	t.Cleanup(func() {
		defer f.Close()
		if !t.Failed() {
			return
		}

		data, err := io.ReadAll(f)
		if err != nil {
			t.Errorf("reading syslog file: %v", err)
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			// softhsm tags the syslog files using the binary name, not "softhsm"
			// or a related string. Logs were tagged with "pkcs11.test".
			if !strings.Contains(line, "pkcs11") {
				continue
			}

			t.Logf("%s", line)
		}
	})

	// See softhsm2.conf(5) for config details
	configPath := filepath.Join(t.TempDir(), "softhsm.conf")
	tokensPath := filepath.Join(t.TempDir(), "tokens")
	if err := os.Mkdir(tokensPath, 0755); err != nil {
		t.Fatalf("create test tokens directory: %v", err)
	}

	configData := fmt.Sprintf(`
directories.tokendir = %s
`, tokensPath)
	if err := os.WriteFile(configPath, []byte(configData), 0644); err != nil {
		t.Fatalf("write softhsm config: %v", err)
	}
	t.Setenv("SOFTHSM2_CONF", configPath)

	m, err := Open(libSoftHSMPath)
	if err != nil {
		t.Fatalf("Open(%s): %v", libSoftHSMPath, err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Errorf("Close module: %v", err)
		}
	})
	return m
}

func TestNewModule(t *testing.T) {
	newTestModule(t)
}

func TestSlotInit(t *testing.T) {
	m := newTestModule(t)
	if err := m.SlotInitialize(0, "test", "1234"); err != nil {
		t.Fatalf("SlotInitialize(0, 'test', '1234'): %v", err)
	}
}

func TestSlotIDs(t *testing.T) {
	m := newTestModule(t)
	got, err := m.SlotIDs()
	if err != nil {
		t.Fatalf("SlotIDs(): %v", err)
	}
	want := []uint32{0}
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SlotIDs() returned unexpected value, got %v, want %v", got, want)
	}
}

func TestInfo(t *testing.T) {
	m := newTestModule(t)
	info := m.Info()

	wantMan := "SoftHSM"
	if info.Manufacturer != wantMan {
		t.Errorf("SlotInfo() unexpected manufacturer, got %s, want %s", info.Manufacturer, wantMan)
	}
}

func TestSlotInfo(t *testing.T) {
	m := newTestModule(t)
	if err := m.SlotInitialize(0, "test", "1234"); err != nil {
		t.Fatalf("SlotInitialize(0, 'test', '1234'): %v", err)
	}

	info, err := m.SlotInfo(0)
	if err != nil {
		t.Fatalf("SlotInfo(0): %v", err)
	}
	wantLabel := "test"
	if info.Label != wantLabel {
		t.Errorf("SlotInfo() unexpected label, got %s, want %s", info.Label, wantLabel)
	}
}

func TestSlot(t *testing.T) {
	tests := []struct {
		name string
		opts []SlotOption
	}{
		{"Default", []SlotOption{}},
		{"RWSession", []SlotOption{SlotReadWrite()}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := newTestModule(t)
			if err := m.SlotInitialize(0, "test", "1234"); err != nil {
				t.Fatalf("SlotInitialize(0, 'test', '1234'): %v", err)
			}

			s, err := m.Slot(0, test.opts...)
			if err != nil {
				t.Fatalf("Slot(0): %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatalf("Close(): %v", err)
			}
		})
	}
}

func TestGenerateECDSA(t *testing.T) {
	tests := []struct {
		name  string
		curve ECDSACurve
	}{
		{"P256", P256},
		{"P384", P384},
		{"P521", P521},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := newTestModule(t)
			if err := m.SlotInitialize(0, "test", "1234"); err != nil {
				t.Fatalf("SlotInitialize(0, 'test', '1234'): %v", err)
			}

			s, err := m.Slot(0, SlotReadWrite())
			if err != nil {
				t.Fatalf("Slot(0): %v", err)
			}
			defer s.Close()
			if err := s.LoginAdmin("1234"); err != nil {
				t.Fatalf("authenicating as admin: %v", err)
			}

			if err := s.InitPIN("12345"); err != nil {
				t.Fatalf("initializing user pin: %v", err)
			}

			if err := s.Logout(); err != nil {
				t.Fatalf("logout: %v", err)
			}

			if err := s.Login("12345"); err != nil {
				t.Fatalf("authenicating as admin: %v", err)
			}

			o := GenerateECDSA{Curve: test.curve}
			if _, err := s.Generate(o); err != nil {
				t.Fatalf("Generate(%#v) failed: %v", o, err)
			}
		})
	}
}

func TestObjects(t *testing.T) {
	tests := []struct {
		name string
		opts []ObjectOption
		want []Class
	}{
		{"AllObjects", []ObjectOption{}, []Class{ClassPublicKey, ClassPrivateKey}},
		{"PrivateKey", []ObjectOption{ObjectClass(ClassPrivateKey)}, []Class{ClassPrivateKey}},
		{"PublicKey", []ObjectOption{ObjectClass(ClassPublicKey)}, []Class{ClassPublicKey}},
		{"ByLabel", []ObjectOption{ObjectLabel("privatekey")}, []Class{ClassPrivateKey}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := newTestModule(t)
			if err := m.SlotInitialize(0, "test", "1234"); err != nil {
				t.Fatalf("SlotInitialize(0, 'test', '1234'): %v", err)
			}

			s, err := m.Slot(0, SlotReadWrite())
			if err != nil {
				t.Fatalf("Slot(0): %v", err)
			}
			defer s.Close()
			if err := s.LoginAdmin("1234"); err != nil {
				t.Fatalf("authenicating as admin: %v", err)
			}

			if err := s.InitPIN("12345"); err != nil {
				t.Fatalf("initializing user pin: %v", err)
			}

			if err := s.Logout(); err != nil {
				t.Fatalf("logout: %v", err)
			}

			if err := s.Login("12345"); err != nil {
				t.Fatalf("authenicating as admin: %v", err)
			}

			o := GenerateECDSA{
				Curve:        P256,
				PrivateLabel: "privatekey",
				PublicLabel:  "publickey",
			}
			if _, err := s.Generate(o); err != nil {
				t.Fatalf("Generate(%#v) failed: %v", o, err)
			}

			objs, err := s.Objects(test.opts...)
			if err != nil {
				t.Fatalf("Slot(0).Objects(): %v", err)
			}

			var got []Class
			for _, o := range objs {
				got = append(got, o.Class())
			}
			sort.Slice(test.want, func(i, j int) bool { return test.want[i] < test.want[j] })
			sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })

			if !reflect.DeepEqual(test.want, got) {
				t.Fatalf("Objects() classes mismatch, got %v, want %v", got, test.want)
			}
		})
	}
}

// Generated with:
// openssl req -subj '/CN=test' -nodes -x509 -newkey rsa:4096 -keyout /dev/null -out /dev/stdout -days 365
const testCertData = `-----BEGIN CERTIFICATE-----
MIIE/zCCAuegAwIBAgIUSxn81BYTB9S1zx4v6EhCOvx5PU8wDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yMTA5MjkwMDI3NTBaFw0yMjA5MjkwMDI3
NTBaMA8xDTALBgNVBAMMBHRlc3QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQC8boHADxkGDGGRlR2GhhkfT7i/+7KrLg/2Px12dIpATtfAOB2gK0sHZpQ3
cui8MKm6dtICpY7sV+9ZTNGpeiTRxoJ+/9KhzMNwOgY8bBUR8QdFrLOW7pdxuJqs
MLJ6IZKyAb02bwHBcBZbsMOVWK8iqMolsdJ6fPYC+aRRExfQg2dEMX7utGbolBLq
IADgmEVeYH2oRDED+a0MSO8nRsO2ef+L6dB038z+xop5kPwjlyEaF8se/arZhfzN
Tgv0m5FYeNXIdwDRqb1vhKXIRC6HkHkdjyGpJhjx+S+mtAITO/wjiuXVdiq37qQi
aIfP7iahmYCmfFleG/czQWs0DPaAXOlOKCdteeUwhPEN9LAXp4LJTukUiidNvtxq
eb7cRo6rucUSLur3rbaGq/YuSHbHeBLS6VrBQ9QZH1fTCsWqhAhR8zz7qqZZk1M7
LBdsOOByxEAKj9IVkXtQDWeL4iH4PrV8fGb+grrqja6IvgPOm7jO2AbCubPR5V02
yhIAggZIOx3Mu93qzxcrn1Y5TH4QhqgCa8Mvxe2mQrZlla3lTLFY6SW3/N3iMqzb
rZx4u/QThCIovrNUr11RhNU4unFrFIHWWrQg52Zh6dxs7y7lwmtV1a4trtM54jsK
DmBWGovSSRwmrOHyp5xSUWTIe0cF4yhgXzKYZsB8kcKzQoX8TwIDAQABo1MwUTAd
BgNVHQ4EFgQUZzvuma3BmzFhKWb64Y2PVq/+aK0wHwYDVR0jBBgwFoAUZzvuma3B
mzFhKWb64Y2PVq/+aK0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AgEAGTtRUGa1Xhx633QWPFgdx3Ylg1paIve882AT1mUN+MyJ88Cx1wvXQwJsf2TI
6iE4uj2PLQvpt6mrNqT1ItdN4iyfCiXqkzZJ1uXOnneJujk+IuhHbUgP78vYSrZO
2akl9S3BgwvDLcV6EOXfo5ERU8rTWfYu64tDNQcaxP0pNoyD6um5BsmB2Jxznn4F
HbrQcBFh4hli1cAbjXeXWgnWuT6Ajz0L98fKaDhx3D7ggMPYd64/XVQBZSw2gCRJ
9i26kFdbmLz6nDq8RKoiXy8dOgtyCj26QevoDlsq5fIdqDATScKL1/cKBFiwT2h0
nbxl1SqoXvP4QRuB7444LEmPrU2TIIhaICoHnCTmr5P2CB4PL8KggVyKHWb3eYR9
5/HsXJA21uQqezNhr+mKTtAob4kpWt1MoICul7uIy4fwjeCcCQpOCBlVt11uroN+
0OqSY5CDjQfZ+2C1gLdKUZ7nomRuBdxWh+f48dtIh46vkw/dXN5prmU7j8QoAbfr
40+3biWKDfbCJ0auEucdM3tLGxim1HlKf7ROmrrS8gEBH23Ww3ibKPBnNiQvTK/L
nBPryTEU4DaFuWh36J5tGuqZFCo9S58dCmajvhAMs2hpw4u6tLCaiaqtUByGnDv9
6ymrXrM0Nw+Ri1Lz+EMZ71I5uC4BItv+uZNm3XJz+/CDrMw=
-----END CERTIFICATE-----`

func mustParseCertificate(s string) *x509.Certificate {
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		panic("no pem data in certificate")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		panic("parse certificate: " + err.Error())
	}
	return cert
}

func TestCreateCertificate(t *testing.T) {
	m := newTestModule(t)
	if err := m.SlotInitialize(0, "test", "1234"); err != nil {
		t.Fatalf("SlotInitialize(0, 'test', '1234'): %v", err)
	}

	s, err := m.Slot(0, SlotReadWrite())
	if err != nil {
		t.Fatalf("Slot(0): %v", err)
	}
	defer s.Close()
	if err := s.LoginAdmin("1234"); err != nil {
		t.Fatalf("authenicating as admin: %v", err)
	}

	if err := s.InitPIN("12345"); err != nil {
		t.Fatalf("initializing user pin: %v", err)
	}

	if err := s.Logout(); err != nil {
		t.Fatalf("logout: %v", err)
	}

	if err := s.Login("12345"); err != nil {
		t.Fatalf("authenicating as admin: %v", err)
	}

	cert := mustParseCertificate(testCertData)

	want := "testcert"
	opt := CreateX509Certificate{
		Certificate: cert,
		Label:       want,
	}
	o, err := s.Create(opt)
	if err != nil {
		t.Fatalf("Create(%v) %v", opt, err)
	}
	got, err := o.Label()
	if err != nil {
		t.Fatalf("Label(): %v", err)
	}
	if got != want {
		t.Errorf("Label() did not match, got %s, want %s", got, want)
	}

	if err := o.SetLabel("bar"); err != nil {
		t.Fatalf("SetLabel(): %v", err)
	}
	want = "bar"
	got, err = o.Label()
	if err != nil {
		t.Fatalf("Label(): %v", err)
	}
	if got != want {
		t.Errorf("Label() did not match after setting it, got %s, want %s", got, want)
	}
}
