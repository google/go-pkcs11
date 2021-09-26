package pkcs11

/*
#include <dlfcn.h>
#include <stdlib.h>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

// Go can't call a C function pointer directly, so these are wrappers that
// perform the dereference in C.

CK_RV get_function_list(CK_C_GetFunctionList fn, CK_FUNCTION_LIST_PTR_PTR p) {
	return (*fn)(p);
}

CK_RV ck_initialize(CK_FUNCTION_LIST_PTR fl, CK_C_INITIALIZE_ARGS_PTR args) {
	return (*fl->C_Initialize)((CK_VOID_PTR)(args));
}

CK_RV ck_finalize(CK_FUNCTION_LIST_PTR fl) {
	return (*fl->C_Finalize)(NULL_PTR);
}

CK_RV ck_init_token(
	CK_FUNCTION_LIST_PTR fl,
	CK_SLOT_ID      slotID,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG        ulPinLen,
	CK_UTF8CHAR_PTR pLabel
) {
	if (ulPinLen == 0) {
		// TODO(ericchiang): This isn't tested since softhsm requires a PIN.
		pPin = NULL_PTR;
	}
	return (*fl->C_InitToken)(slotID, pPin, ulPinLen, pLabel);
}

CK_RV ck_get_slot_list(
	CK_FUNCTION_LIST_PTR fl,
	CK_SLOT_ID_PTR pSlotList,
	CK_ULONG_PTR pulCount
) {
	return (*fl->C_GetSlotList)(CK_FALSE, pSlotList, pulCount);
}
*/
// #cgo linux LDFLAGS: -ldl
import "C"
import (
	"fmt"
	"unsafe"
)

// Error is returned for cryptokit specific API codes.
type Error struct {
	fnName string
	code   C.CK_RV
}

func (e *Error) Error() string {
	return fmt.Sprintf("pkcs11: %s() 0x%x", e.fnName, e.code)
}

func isOk(fnName string, rv C.CK_RV) error {
	if rv == C.CKR_OK {
		return nil
	}
	return &Error{fnName, rv}
}

// Module represents an opened shared library. By default, this package
// requests locking support from the module, but concurrent safety may
// depend on the underlying library.
type Module struct {
	mod unsafe.Pointer
	fl  C.CK_FUNCTION_LIST_PTR
}

// Open dlopens a shared library by path, initializing the module.
func Open(path string) (*Module, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	mod := C.dlopen(cPath, C.RTLD_NOW)
	if mod == nil {
		return nil, fmt.Errorf("pkcs11: dlopen error: %s", C.GoString(C.dlerror()))
	}

	cSym := C.CString("C_GetFunctionList")
	defer C.free(unsafe.Pointer(cSym))

	getFuncListFn := (C.CK_C_GetFunctionList)(C.dlsym(mod, cSym))
	if getFuncListFn == nil {
		err := fmt.Errorf("pkcs11: lookup function list symbol: %s", C.GoString(C.dlerror()))
		C.dlclose(mod)
		return nil, err
	}

	var p C.CK_FUNCTION_LIST_PTR
	rv := C.get_function_list(getFuncListFn, &p)
	if err := isOk("C_GetFunctionList", rv); err != nil {
		C.dlclose(mod)
		return nil, err
	}

	args := C.CK_C_INITIALIZE_ARGS{
		flags: C.CKF_OS_LOCKING_OK,
	}
	if err := isOk("C_Initialize", C.ck_initialize(p, &args)); err != nil {
		C.dlclose(mod)
		return nil, err
	}

	return &Module{
		mod: mod,
		fl:  p,
	}, nil
}

// Close finalizes the module and releases any resources associated with the
// shared library.
func (m *Module) Close() error {
	if err := isOk("C_Finalize", C.ck_finalize(m.fl)); err != nil {
		return err
	}
	if C.dlclose(m.mod) != 0 {
		return fmt.Errorf("pkcs11: dlclose error: %s", C.GoString(C.dlerror()))
	}
	return nil
}

func ckStringPadded(b []C.CK_UTF8CHAR, s string) bool {
	if len(s) > len(b) {
		return false
	}
	for i := range b {
		if i < len(s) {
			b[i] = C.CK_UTF8CHAR(s[i])
		} else {
			b[i] = C.CK_UTF8CHAR(' ')
		}
	}
	return true
}

func ckString(s string) []C.CK_UTF8CHAR {
	b := make([]C.CK_UTF8CHAR, len(s))
	for i, c := range []byte(s) {
		b[i] = C.CK_UTF8CHAR(c)
	}
	return b
}

// SlotInitialize configures a slot object. Internally this calls C_InitToken.
//
// Different modules have different restrictions on the PIN value, and some
// may refuse an empty PIN.
func (m *Module) SlotInitialize(slotID uint32, label, pin string) error {
	var cLabel [32]C.CK_UTF8CHAR
	if !ckStringPadded(cLabel[:], label) {
		return fmt.Errorf("pkcs11: label too long")
	}

	cPIN := ckString(pin)
	cPINLen := C.CK_ULONG(len(cPIN))

	var cPINPtr C.CK_UTF8CHAR_PTR
	if len(pin) > 0 {
		cPINPtr = &cPIN[0]
	}

	rv := C.ck_init_token(
		m.fl,
		C.CK_SLOT_ID(slotID),
		cPINPtr,
		cPINLen,
		&cLabel[0],
	)
	if err := isOk("C_InitToken", rv); err != nil {
		return err
	}

	return nil
}

// SlotIDs returns the IDs of all slots associated with this module, including
// ones that haven't been initalized.
func (m *Module) SlotIDs() ([]uint32, error) {
	var n C.CK_ULONG
	rv := C.ck_get_slot_list(m.fl, nil, &n)
	if err := isOk("C_GetSlotList", rv); err != nil {
		return nil, err
	}

	l := make([]C.CK_SLOT_ID, int(n))
	rv = C.ck_get_slot_list(m.fl, &l[0], &n)
	if err := isOk("C_GetSlotList", rv); err != nil {
		return nil, err
	}
	if int(n) > len(l) {
		return nil, fmt.Errorf("pkcs11: C_GetSlotList returned too many elements, got %d, want %d", int(n), len(l))
	}
	l = l[:int(n)]

	ids := make([]uint32, len(l))
	for i, id := range l {
		ids[i] = uint32(id)
	}
	return ids, nil
}
