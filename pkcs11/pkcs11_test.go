package pkcs11

import (
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
