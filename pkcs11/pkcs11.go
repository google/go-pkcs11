// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package pkcs11 implements logic for using PKCS #11 shared libraries.
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

#include "../third_party/pkcs11/pkcs11.h"

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

CK_RV ck_get_info(
	CK_FUNCTION_LIST_PTR fl,
	CK_INFO_PTR pInfo
) {
	return (*fl->C_GetInfo)(pInfo);
}

CK_RV ck_get_slot_info(
	CK_FUNCTION_LIST_PTR fl,
	CK_SLOT_ID slotID,
	CK_SLOT_INFO_PTR pInfo
) {
	return (*fl->C_GetSlotInfo)(slotID, pInfo);
}

CK_RV ck_get_token_info(
	CK_FUNCTION_LIST_PTR fl,
	CK_SLOT_ID slotID,
	CK_TOKEN_INFO_PTR pInfo
) {
	return (*fl->C_GetTokenInfo)(slotID, pInfo);
}

CK_RV ck_open_session(
	CK_FUNCTION_LIST_PTR fl,
	CK_SLOT_ID slotID,
	CK_FLAGS flags,
	CK_SESSION_HANDLE_PTR phSession
) {
	return (*fl->C_OpenSession)(slotID, flags, NULL_PTR, NULL_PTR, phSession);
}

CK_RV ck_close_session(
	CK_FUNCTION_LIST_PTR fl,
	CK_SESSION_HANDLE hSession
) {
	return (*fl->C_CloseSession)(hSession);
}

CK_RV ck_login(
	CK_FUNCTION_LIST_PTR fl,
	CK_SESSION_HANDLE hSession,
	CK_USER_TYPE userType,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen
) {
	return (*fl->C_Login)(hSession, userType, pPin, ulPinLen);
}

CK_RV ck_logout(
	CK_FUNCTION_LIST_PTR fl,
	CK_SESSION_HANDLE hSession
) {
	return (*fl->C_Logout)(hSession);
}

CK_RV ck_init_pin(
	CK_FUNCTION_LIST_PTR fl,
	CK_SESSION_HANDLE hSession,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen
) {
	return (*fl->C_InitPIN)(hSession, pPin, ulPinLen);
}

CK_RV ck_generate_key_pair(
	CK_FUNCTION_LIST_PTR fl,
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey
) {
	return (*fl->C_GenerateKeyPair)(
		hSession,
		pMechanism,
		pPublicKeyTemplate,
		ulPublicKeyAttributeCount,
		pPrivateKeyTemplate,
		ulPrivateKeyAttributeCount,
		phPublicKey,
		phPrivateKey
	);
}

CK_RV ck_find_objects_init(
	CK_FUNCTION_LIST_PTR fl,
	CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount
) {
	return (*fl->C_FindObjectsInit)(hSession, pTemplate, ulCount);
}

CK_RV ck_find_objects(
	CK_FUNCTION_LIST_PTR fl,
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE_PTR phObject,
	CK_ULONG ulMaxObjectCount,
	CK_ULONG_PTR pulObjectCount
) {
	return (*fl->C_FindObjects)(hSession, phObject, ulMaxObjectCount, pulObjectCount);
}

CK_RV ck_find_objects_final(
	CK_FUNCTION_LIST_PTR fl,
	CK_SESSION_HANDLE hSession
) {
	return (*fl->C_FindObjectsFinal)(hSession);
}

CK_RV ck_create_object(
	CK_FUNCTION_LIST_PTR fl,
	CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phObject
) {
	return (*fl->C_CreateObject)(hSession, pTemplate, ulCount, phObject);
}

CK_RV ck_get_attribute_value(
	CK_FUNCTION_LIST_PTR fl,
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount
) {
	return (*fl->C_GetAttributeValue)(hSession, hObject, pTemplate, ulCount);
}

CK_RV ck_set_attribute_value(
	CK_FUNCTION_LIST_PTR fl,
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount
) {
	return (*fl->C_SetAttributeValue)(hSession, hObject, pTemplate, ulCount);
}

CK_RV ck_sign_init(
	CK_FUNCTION_LIST_PTR fl,
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey
) {
	return (*fl->C_SignInit)(hSession, pMechanism, hKey);
}

CK_RV ck_sign(
	CK_FUNCTION_LIST_PTR fl,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData,
	CK_ULONG ulDataLen,
	CK_BYTE_PTR pSignature,
	CK_ULONG_PTR pulSignatureLen
) {
	return (*fl->C_Sign)(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}

CK_RV ck_decrypt_init(
	CK_FUNCTION_LIST_PTR fl,
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR  pMechanism,
	CK_OBJECT_HANDLE  hKey
) {
	return (*fl->C_DecryptInit)(hSession, pMechanism, hKey);
}

CK_RV ck_decrypt(
	CK_FUNCTION_LIST_PTR fl,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR       pEncryptedData,
	CK_ULONG          ulEncryptedDataLen,
	CK_BYTE_PTR       pData,
	CK_ULONG_PTR      pulDataLen
) {
	return (*fl->C_Decrypt)(hSession, pEncryptedData,  ulEncryptedDataLen, pData, pulDataLen);
}
*/
// #cgo linux LDFLAGS: -ldl
import "C"
import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"strings"
	"unsafe"
)

// ckStringPadded copies a string into b, padded with ' '. If the string is larger
// than the provided buffer, this function returns false.
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

// ckString converts a Go string to a cryptokit string. The string is still held
// by Go memory and doesn't need to be freed.
func ckString(s string) []C.CK_UTF8CHAR {
	b := make([]C.CK_UTF8CHAR, len(s))
	for i, c := range []byte(s) {
		b[i] = C.CK_UTF8CHAR(c)
	}
	return b
}

// ckCString converts a Go string to a cryptokit string held by C. This is required,
// for example, when building a CK_ATTRIBUTE, which needs to hold a pointer to a
// cryptokit string.
//
// This method also returns a function to free the allocated C memory.
func ckCString(s string) (cstring *C.CK_UTF8CHAR, free func()) {
	b := (*C.CK_UTF8CHAR)(C.malloc(C.sizeof_CK_UTF8CHAR * C.ulong(len(s))))
	bs := unsafe.Slice(b, len(s))
	for i, c := range []byte(s) {
		bs[i] = C.CK_UTF8CHAR(c)
	}
	return b, func() { C.free(unsafe.Pointer(b)) }
}

func ckGoString(s *C.CK_UTF8CHAR, n C.CK_ULONG) string {
	var sb strings.Builder
	sli := unsafe.Slice(s, n)
	for _, b := range sli {
		sb.WriteByte(byte(b))
	}
	return sb.String()
}

// Error is returned for cryptokit specific API codes.
type Error struct {
	fnName string
	code   C.CK_RV
}

func (e *Error) Error() string {
	code, ok := ckRVString[e.code]
	if !ok {
		code = fmt.Sprintf("0x%x", e.code)
	}
	return fmt.Sprintf("pkcs11: %s() %s", e.fnName, code)
}

var ckRVString = map[C.CK_RV]string{
	C.CKR_CANCEL:                           "CKR_CANCEL",
	C.CKR_HOST_MEMORY:                      "CKR_HOST_MEMORY",
	C.CKR_SLOT_ID_INVALID:                  "CKR_SLOT_ID_INVALID",
	C.CKR_GENERAL_ERROR:                    "CKR_GENERAL_ERROR",
	C.CKR_FUNCTION_FAILED:                  "CKR_FUNCTION_FAILED",
	C.CKR_ARGUMENTS_BAD:                    "CKR_ARGUMENTS_BAD",
	C.CKR_NO_EVENT:                         "CKR_NO_EVENT",
	C.CKR_NEED_TO_CREATE_THREADS:           "CKR_NEED_TO_CREATE_THREADS",
	C.CKR_CANT_LOCK:                        "CKR_CANT_LOCK",
	C.CKR_ATTRIBUTE_READ_ONLY:              "CKR_ATTRIBUTE_READ_ONLY",
	C.CKR_ATTRIBUTE_SENSITIVE:              "CKR_ATTRIBUTE_SENSITIVE",
	C.CKR_ATTRIBUTE_TYPE_INVALID:           "CKR_ATTRIBUTE_TYPE_INVALID",
	C.CKR_ATTRIBUTE_VALUE_INVALID:          "CKR_ATTRIBUTE_VALUE_INVALID",
	C.CKR_ACTION_PROHIBITED:                "CKR_ACTION_PROHIBITED",
	C.CKR_DATA_INVALID:                     "CKR_DATA_INVALID",
	C.CKR_DATA_LEN_RANGE:                   "CKR_DATA_LEN_RANGE",
	C.CKR_DEVICE_ERROR:                     "CKR_DEVICE_ERROR",
	C.CKR_DEVICE_MEMORY:                    "CKR_DEVICE_MEMORY",
	C.CKR_DEVICE_REMOVED:                   "CKR_DEVICE_REMOVED",
	C.CKR_ENCRYPTED_DATA_INVALID:           "CKR_ENCRYPTED_DATA_INVALID",
	C.CKR_ENCRYPTED_DATA_LEN_RANGE:         "CKR_ENCRYPTED_DATA_LEN_RANGE",
	C.CKR_FUNCTION_CANCELED:                "CKR_FUNCTION_CANCELED",
	C.CKR_FUNCTION_NOT_PARALLEL:            "CKR_FUNCTION_NOT_PARALLEL",
	C.CKR_FUNCTION_NOT_SUPPORTED:           "CKR_FUNCTION_NOT_SUPPORTED",
	C.CKR_KEY_HANDLE_INVALID:               "CKR_KEY_HANDLE_INVALID",
	C.CKR_KEY_SIZE_RANGE:                   "CKR_KEY_SIZE_RANGE",
	C.CKR_KEY_TYPE_INCONSISTENT:            "CKR_KEY_TYPE_INCONSISTENT",
	C.CKR_KEY_NOT_NEEDED:                   "CKR_KEY_NOT_NEEDED",
	C.CKR_KEY_CHANGED:                      "CKR_KEY_CHANGED",
	C.CKR_KEY_NEEDED:                       "CKR_KEY_NEEDED",
	C.CKR_KEY_INDIGESTIBLE:                 "CKR_KEY_INDIGESTIBLE",
	C.CKR_KEY_FUNCTION_NOT_PERMITTED:       "CKR_KEY_FUNCTION_NOT_PERMITTED",
	C.CKR_KEY_NOT_WRAPPABLE:                "CKR_KEY_NOT_WRAPPABLE",
	C.CKR_KEY_UNEXTRACTABLE:                "CKR_KEY_UNEXTRACTABLE",
	C.CKR_MECHANISM_INVALID:                "CKR_MECHANISM_INVALID",
	C.CKR_MECHANISM_PARAM_INVALID:          "CKR_MECHANISM_PARAM_INVALID",
	C.CKR_OBJECT_HANDLE_INVALID:            "CKR_OBJECT_HANDLE_INVALID",
	C.CKR_OPERATION_ACTIVE:                 "CKR_OPERATION_ACTIVE",
	C.CKR_OPERATION_NOT_INITIALIZED:        "CKR_OPERATION_NOT_INITIALIZED",
	C.CKR_PIN_INCORRECT:                    "CKR_PIN_INCORRECT",
	C.CKR_PIN_INVALID:                      "CKR_PIN_INVALID",
	C.CKR_PIN_LEN_RANGE:                    "CKR_PIN_LEN_RANGE",
	C.CKR_PIN_EXPIRED:                      "CKR_PIN_EXPIRED",
	C.CKR_PIN_LOCKED:                       "CKR_PIN_LOCKED",
	C.CKR_SESSION_CLOSED:                   "CKR_SESSION_CLOSED",
	C.CKR_SESSION_COUNT:                    "CKR_SESSION_COUNT",
	C.CKR_SESSION_HANDLE_INVALID:           "CKR_SESSION_HANDLE_INVALID",
	C.CKR_SESSION_PARALLEL_NOT_SUPPORTED:   "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
	C.CKR_SESSION_READ_ONLY:                "CKR_SESSION_READ_ONLY",
	C.CKR_SESSION_EXISTS:                   "CKR_SESSION_EXISTS",
	C.CKR_SESSION_READ_ONLY_EXISTS:         "CKR_SESSION_READ_ONLY_EXISTS",
	C.CKR_SESSION_READ_WRITE_SO_EXISTS:     "CKR_SESSION_READ_WRITE_SO_EXISTS",
	C.CKR_SIGNATURE_INVALID:                "CKR_SIGNATURE_INVALID",
	C.CKR_SIGNATURE_LEN_RANGE:              "CKR_SIGNATURE_LEN_RANGE",
	C.CKR_TEMPLATE_INCOMPLETE:              "CKR_TEMPLATE_INCOMPLETE",
	C.CKR_TEMPLATE_INCONSISTENT:            "CKR_TEMPLATE_INCONSISTENT",
	C.CKR_TOKEN_NOT_PRESENT:                "CKR_TOKEN_NOT_PRESENT",
	C.CKR_TOKEN_NOT_RECOGNIZED:             "CKR_TOKEN_NOT_RECOGNIZED",
	C.CKR_TOKEN_WRITE_PROTECTED:            "CKR_TOKEN_WRITE_PROTECTED",
	C.CKR_UNWRAPPING_KEY_HANDLE_INVALID:    "CKR_UNWRAPPING_KEY_HANDLE_INVALID",
	C.CKR_UNWRAPPING_KEY_SIZE_RANGE:        "CKR_UNWRAPPING_KEY_SIZE_RANGE",
	C.CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT",
	C.CKR_USER_ALREADY_LOGGED_IN:           "CKR_USER_ALREADY_LOGGED_IN",
	C.CKR_USER_NOT_LOGGED_IN:               "CKR_USER_NOT_LOGGED_IN",
	C.CKR_USER_PIN_NOT_INITIALIZED:         "CKR_USER_PIN_NOT_INITIALIZED",
	C.CKR_USER_TYPE_INVALID:                "CKR_USER_TYPE_INVALID",
	C.CKR_USER_ANOTHER_ALREADY_LOGGED_IN:   "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
	C.CKR_USER_TOO_MANY_TYPES:              "CKR_USER_TOO_MANY_TYPES",
	C.CKR_WRAPPED_KEY_INVALID:              "CKR_WRAPPED_KEY_INVALID",
	C.CKR_WRAPPED_KEY_LEN_RANGE:            "CKR_WRAPPED_KEY_LEN_RANGE",
	C.CKR_WRAPPING_KEY_HANDLE_INVALID:      "CKR_WRAPPING_KEY_HANDLE_INVALID",
	C.CKR_WRAPPING_KEY_SIZE_RANGE:          "CKR_WRAPPING_KEY_SIZE_RANGE",
	C.CKR_WRAPPING_KEY_TYPE_INCONSISTENT:   "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
	C.CKR_RANDOM_SEED_NOT_SUPPORTED:        "CKR_RANDOM_SEED_NOT_SUPPORTED",
	C.CKR_RANDOM_NO_RNG:                    "CKR_RANDOM_NO_RNG",
	C.CKR_DOMAIN_PARAMS_INVALID:            "CKR_DOMAIN_PARAMS_INVALID",
	C.CKR_CURVE_NOT_SUPPORTED:              "CKR_CURVE_NOT_SUPPORTED",
	C.CKR_BUFFER_TOO_SMALL:                 "CKR_BUFFER_TOO_SMALL",
	C.CKR_SAVED_STATE_INVALID:              "CKR_SAVED_STATE_INVALID",
	C.CKR_INFORMATION_SENSITIVE:            "CKR_INFORMATION_SENSITIVE",
	C.CKR_STATE_UNSAVEABLE:                 "CKR_STATE_UNSAVEABLE",
	C.CKR_CRYPTOKI_NOT_INITIALIZED:         "CKR_CRYPTOKI_NOT_INITIALIZED",
	C.CKR_CRYPTOKI_ALREADY_INITIALIZED:     "CKR_CRYPTOKI_ALREADY_INITIALIZED",
	C.CKR_MUTEX_BAD:                        "CKR_MUTEX_BAD",
	C.CKR_MUTEX_NOT_LOCKED:                 "CKR_MUTEX_NOT_LOCKED",
	C.CKR_FUNCTION_REJECTED:                "CKR_FUNCTION_REJECTED",
	C.CKR_VENDOR_DEFINED:                   "CKR_VENDOR_DEFINED",
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
	// mod is a pointer to the dlopen handle. Kept around to dlfree
	// when the Module is closed.
	mod unsafe.Pointer
	// List of C functions provided by the module.
	fl C.CK_FUNCTION_LIST_PTR
	// Version of the module, used for compatibility.
	version C.CK_VERSION

	info Info
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

	var info C.CK_INFO
	if err := isOk("C_GetInfo", C.ck_get_info(p, &info)); err != nil {
		C.dlclose(mod)
		return nil, err
	}

	return &Module{
		mod:     mod,
		fl:      p,
		version: info.cryptokiVersion,
		info: Info{
			Manufacturer: toString(info.manufacturerID[:]),
			Version: Version{
				Major: uint8(info.libraryVersion.major),
				Minor: uint8(info.libraryVersion.minor),
			},
		},
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

// createSlot configures a slot object. Internally this calls C_InitToken and
// C_InitPIN to set the admin and user PIN on the slot.
func (m *Module) createSlot(id uint32, opts slotOptions) error {
	if opts.Label == "" {
		return fmt.Errorf("no label provided")
	}
	if opts.PIN == "" {
		return fmt.Errorf("no user pin provided")
	}
	if opts.AdminPIN == "" {
		return fmt.Errorf("no admin pin provided")
	}

	var cLabel [32]C.CK_UTF8CHAR
	if !ckStringPadded(cLabel[:], opts.Label) {
		return fmt.Errorf("pkcs11: label too long")
	}

	cPIN := ckString(opts.AdminPIN)
	cPINLen := C.CK_ULONG(len(cPIN))

	rv := C.ck_init_token(
		m.fl,
		C.CK_SLOT_ID(id),
		&cPIN[0],
		cPINLen,
		&cLabel[0],
	)
	if err := isOk("C_InitToken", rv); err != nil {
		return err
	}

	so := Options{
		AdminPIN:  opts.AdminPIN,
		ReadWrite: true,
	}
	s, err := m.Slot(id, so)
	if err != nil {
		return fmt.Errorf("getting slot: %w", err)
	}
	defer s.Close()
	if err := s.initPIN(opts.PIN); err != nil {
		return fmt.Errorf("configuring user pin: %w", err)
	}
	if err := s.logout(); err != nil {
		return fmt.Errorf("logout: %v", err)
	}
	return nil
}

// SlotIDs returns the IDs of all slots associated with this module, including
// ones that haven't been initialized.
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

// Version holds a major and minor version.
type Version struct {
	Major uint8
	Minor uint8
}

// Info holds global information about the module.
type Info struct {
	// Manufacturer of the implementation. When multiple PKCS #11 devices are
	// present this is used to differentiate devices.
	Manufacturer string
	// Version of the module.
	Version Version
	// Human readable description of the module.
	Description string
}

// SlotInfo holds information about the slot and underlying token.
type SlotInfo struct {
	Label  string
	Model  string
	Serial string

	Description string
}

func toString(b []C.uchar) string {
	lastIndex := len(b)
	for i := len(b); i > 0; i-- {
		if b[i-1] != C.uchar(' ') {
			break
		}
		lastIndex = i - 1
	}

	var sb strings.Builder
	for _, c := range b[:lastIndex] {
		sb.WriteByte(byte(c))
	}
	return sb.String()
}

// Info returns additional information about the module.
func (m *Module) Info() Info {
	return m.info
}

// SlotInfo queries for information about the slot, such as the label.
func (m *Module) SlotInfo(id uint32) (*SlotInfo, error) {
	var (
		cSlotInfo  C.CK_SLOT_INFO
		cTokenInfo C.CK_TOKEN_INFO
		slotID     = C.CK_SLOT_ID(id)
	)
	rv := C.ck_get_slot_info(m.fl, slotID, &cSlotInfo)
	if err := isOk("C_GetSlotInfo", rv); err != nil {
		return nil, err
	}
	info := SlotInfo{
		Description: toString(cSlotInfo.slotDescription[:]),
	}
	if (cSlotInfo.flags & C.CKF_TOKEN_PRESENT) == 0 {
		return &info, nil
	}

	rv = C.ck_get_token_info(m.fl, slotID, &cTokenInfo)
	if err := isOk("C_GetTokenInfo", rv); err != nil {
		return nil, err
	}
	info.Label = toString(cTokenInfo.label[:])
	info.Model = toString(cTokenInfo.model[:])
	info.Serial = toString(cTokenInfo.serialNumber[:])
	return &info, nil
}

// Slot represents a session to a slot.
//
// A slot holds a listable set of objects, such as certificates and
// cryptographic keys.
type Slot struct {
	fl C.CK_FUNCTION_LIST_PTR
	h  C.CK_SESSION_HANDLE
}

type slotOptions struct {
	AdminPIN string
	PIN      string
	Label    string
}

// Options holds configuration options for the slot session.
type Options struct {
	PIN      string
	AdminPIN string
	// ReadWrite indicates that the slot should be opened with write capabilities,
	// such as generating keys or importing certificates.
	//
	// By default, sessions can access objects and perform signing requests.
	ReadWrite bool
}

// Slot creates a session with the given slot, by default read-only. Users
// must call Close to release the session.
//
// The returned Slot's behavior is undefined once the Module is closed.
func (m *Module) Slot(id uint32, opts Options) (*Slot, error) {
	if opts.AdminPIN != "" && opts.PIN != "" {
		return nil, fmt.Errorf("can't specify pin and admin pin")
	}

	var (
		h      C.CK_SESSION_HANDLE
		slotID = C.CK_SLOT_ID(id)
		// "For legacy reasons, the CKF_SERIAL_SESSION bit MUST always be set".
		//
		// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959742
		flags C.CK_FLAGS = C.CKF_SERIAL_SESSION
	)

	if opts.ReadWrite {
		flags = flags | C.CKF_RW_SESSION
	}

	rv := C.ck_open_session(m.fl, slotID, flags, &h)
	if err := isOk("C_OpenSession", rv); err != nil {
		return nil, err
	}

	s := &Slot{fl: m.fl, h: h}

	if opts.PIN != "" {
		if err := s.login(opts.PIN); err != nil {
			s.Close()
			return nil, err
		}
	}
	if opts.AdminPIN != "" {
		if err := s.loginAdmin(opts.AdminPIN); err != nil {
			s.Close()
			return nil, err
		}
	}

	return s, nil
}

// Close releases the slot session.
func (s *Slot) Close() error {
	return isOk("C_CloseSession", C.ck_close_session(s.fl, s.h))
}

// TODO(ericchiang): merge with SlotInitialize.
func (s *Slot) initPIN(pin string) error {
	if pin == "" {
		return fmt.Errorf("invalid pin")
	}
	cPIN := ckString(pin)
	cPINLen := C.CK_ULONG(len(cPIN))
	return isOk("C_InitPIN", C.ck_init_pin(s.fl, s.h, &cPIN[0], cPINLen))
}

func (s *Slot) logout() error {
	return isOk("C_Logout", C.ck_logout(s.fl, s.h))
}

func (s *Slot) login(pin string) error {
	// TODO(ericchiang): check for CKR_USER_ALREADY_LOGGED_IN and auto logout.
	if pin == "" {
		return fmt.Errorf("invalid pin")
	}
	cPIN := ckString(pin)
	cPINLen := C.CK_ULONG(len(cPIN))
	return isOk("C_Login", C.ck_login(s.fl, s.h, C.CKU_USER, &cPIN[0], cPINLen))
}

func (s *Slot) loginAdmin(adminPIN string) error {
	// TODO(ericchiang): maybe run commands, detect CKR_USER_NOT_LOGGED_IN, then
	// automatically login?
	if adminPIN == "" {
		return fmt.Errorf("invalid admin pin")
	}
	cPIN := ckString(adminPIN)
	cPINLen := C.CK_ULONG(len(cPIN))
	return isOk("C_Login", C.ck_login(s.fl, s.h, C.CKU_SO, &cPIN[0], cPINLen))
}

// Class is the primary object type. Such as a certificate, public key, or
// private key.
type Class int

// Set of classes supported by this package.
const (
	ClassData             Class = 0x00000000
	ClassCertificate      Class = 0x00000001
	ClassPublicKey        Class = 0x00000002
	ClassPrivateKey       Class = 0x00000003
	ClassSecretKey        Class = 0x00000004
	ClassDomainParameters Class = 0x00000006
)

var classString = map[Class]string{
	ClassData:             "CKO_DATA",
	ClassCertificate:      "CKO_CERTIFICATE",
	ClassPublicKey:        "CKO_PUBLIC_KEY",
	ClassPrivateKey:       "CKO_PRIVATE_KEY",
	ClassSecretKey:        "CKO_SECRET_KEY",
	ClassDomainParameters: "CKO_DOMAIN_PARAMETERS",
}

// String returns a human readable version of the object class.
func (c Class) String() string {
	if s, ok := classString[c]; ok {
		return s
	}
	return fmt.Sprintf("Class(0x%08x)", int(c))
}

func (c Class) ckType() (C.CK_OBJECT_CLASS, bool) {
	switch c {
	case ClassData:
		return C.CKO_DATA, true
	case ClassCertificate:
		return C.CKO_CERTIFICATE, true
	case ClassPublicKey:
		return C.CKO_PUBLIC_KEY, true
	case ClassPrivateKey:
		return C.CKO_PRIVATE_KEY, true
	case ClassSecretKey:
		return C.CKO_SECRET_KEY, true
	case ClassDomainParameters:
		return C.CKO_DOMAIN_PARAMETERS, true
	}
	return 0, false
}

func (s *Slot) newObject(o C.CK_OBJECT_HANDLE) (Object, error) {
	objClass := C.CK_OBJECT_CLASS_PTR(C.malloc(C.sizeof_CK_OBJECT_CLASS))
	defer C.free(unsafe.Pointer(objClass))

	a := []C.CK_ATTRIBUTE{
		{C.CKA_CLASS, C.CK_VOID_PTR(objClass), C.CK_ULONG(C.sizeof_CK_OBJECT_CLASS)},
	}
	rv := C.ck_get_attribute_value(s.fl, s.h, o, &a[0], C.CK_ULONG(len(a)))
	if err := isOk("C_GetAttributeValue", rv); err != nil {
		return Object{}, err
	}
	return Object{s.fl, s.h, o, *objClass}, nil
}

type createOptions struct {
	Label string

	X509Certificate *x509.Certificate
}

func (s *Slot) create(opts createOptions) (*Object, error) {
	if opts.X509Certificate != nil {
		return s.createX509Certificate(opts)
	}
	return nil, fmt.Errorf("no objects provided to import")
}

// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959709
func (s *Slot) createX509Certificate(opts createOptions) (*Object, error) {
	if opts.X509Certificate == nil {
		return nil, fmt.Errorf("no certificate provided")
	}
	objClass := (*C.CK_OBJECT_CLASS)(C.malloc(C.sizeof_CK_OBJECT_CLASS))
	defer C.free(unsafe.Pointer(objClass))
	*objClass = C.CKO_CERTIFICATE

	ct := (*C.CK_CERTIFICATE_TYPE)(C.malloc(C.sizeof_CK_CERTIFICATE_TYPE))
	defer C.free(unsafe.Pointer(ct))
	*ct = C.CKC_X_509

	cSubj := C.CBytes(opts.X509Certificate.RawSubject)
	defer C.free(cSubj)

	cValue := C.CBytes(opts.X509Certificate.Raw)
	defer C.free(cValue)

	attrs := []C.CK_ATTRIBUTE{
		{C.CKA_CLASS, C.CK_VOID_PTR(objClass), C.CK_ULONG(C.sizeof_CK_OBJECT_CLASS)},
		{C.CKA_CERTIFICATE_TYPE, C.CK_VOID_PTR(ct), C.CK_ULONG(C.sizeof_CK_CERTIFICATE_TYPE)},
		{C.CKA_SUBJECT, C.CK_VOID_PTR(cSubj), C.CK_ULONG(len(opts.X509Certificate.RawSubject))},
		{C.CKA_VALUE, C.CK_VOID_PTR(cValue), C.CK_ULONG(len(opts.X509Certificate.Raw))},
	}

	if opts.Label != "" {
		cs, free := ckCString(opts.Label)
		defer free()

		attrs = append(attrs, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(cs),
			C.CK_ULONG(len(opts.Label)),
		})
	}

	var h C.CK_OBJECT_HANDLE
	rv := C.ck_create_object(s.fl, s.h, &attrs[0], C.CK_ULONG(len(attrs)), &h)
	if err := isOk("C_CreateObject", rv); err != nil {
		return nil, err
	}
	obj, err := s.newObject(h)
	if err != nil {
		return nil, err
	}
	return &obj, nil
}

// Filter hold options for returning a subset of objects from a slot.
//
// The returned object will match all provided parameters. For example, if
// Class=ClassPrivateKey and Label="foo", the returned object must be a
// private key with label "foo".
type Filter struct {
	Class Class
	Label string
}

// Objects searches a slot for objects that match the given options, or all
// objects if no options are provided.
//
// The returned objects behavior is undefined once the Slot object is closed.
func (s *Slot) Objects(opts Filter) (objs []Object, err error) {
	var attrs []C.CK_ATTRIBUTE
	if opts.Label != "" {
		cs, free := ckCString(opts.Label)
		defer free()

		attrs = append(attrs, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(cs),
			C.CK_ULONG(len(opts.Label)),
		})
	}

	if opts.Class != 0 {
		c, ok := Class(opts.Class).ckType()
		if ok {
			objClass := C.CK_OBJECT_CLASS_PTR(C.malloc(C.sizeof_CK_OBJECT_CLASS))
			defer C.free(unsafe.Pointer(objClass))

			*objClass = c
			attrs = append(attrs, C.CK_ATTRIBUTE{
				C.CKA_CLASS,
				C.CK_VOID_PTR(objClass),
				C.CK_ULONG(C.sizeof_CK_OBJECT_CLASS),
			})
		}
	}

	var rv C.CK_RV
	if len(attrs) > 0 {
		rv = C.ck_find_objects_init(s.fl, s.h, &attrs[0], C.CK_ULONG(len(attrs)))
	} else {
		rv = C.ck_find_objects_init(s.fl, s.h, nil, 0)
	}
	if err := isOk("C_FindObjectsInit", rv); err != nil {
		return nil, err
	}
	defer func() {
		rv := C.ck_find_objects_final(s.fl, s.h)
		if ferr := isOk("C_FindObjectsFinal", rv); ferr != nil && err == nil {
			err = ferr
		}
	}()

	var handles []C.CK_OBJECT_HANDLE
	const objectsAtATime = 16
	for {
		cObjHandles := make([]C.CK_OBJECT_HANDLE, objectsAtATime)
		cObjMax := C.CK_ULONG(objectsAtATime)
		var n C.CK_ULONG

		rv := C.ck_find_objects(s.fl, s.h, &cObjHandles[0], cObjMax, &n)
		if err := isOk("C_FindObjects", rv); err != nil {
			return nil, err
		}
		if n == 0 {
			break
		}

		handles = append(handles, cObjHandles[:int(n)]...)
	}

	for _, h := range handles {
		o, err := s.newObject(h)
		if err != nil {
			return nil, err
		}
		objs = append(objs, o)
	}
	return objs, nil
}

// Object represents a single object stored within a slot. For example a key or
// certificate.
type Object struct {
	fl C.CK_FUNCTION_LIST_PTR
	h  C.CK_SESSION_HANDLE
	o  C.CK_OBJECT_HANDLE
	c  C.CK_OBJECT_CLASS
}

// Class returns the type of the object stored. For example, certificate, public
// key, or private key.
func (o Object) Class() Class {
	return Class(int(o.c))
}

func (o Object) getAttribute(attrs []C.CK_ATTRIBUTE) error {
	return isOk("C_GetAttributeValue",
		C.ck_get_attribute_value(o.fl, o.h, o.o, &attrs[0], C.CK_ULONG(len(attrs))),
	)
}

func (o Object) setAttribute(attrs []C.CK_ATTRIBUTE) error {
	return isOk("C_SetAttributeValue",
		C.ck_set_attribute_value(o.fl, o.h, o.o, &attrs[0], C.CK_ULONG(len(attrs))),
	)
}

// Label returns a string value attached to an object, which can be used to
// identify or group sets of keys and certificates.
func (o Object) Label() (string, error) {
	attrs := []C.CK_ATTRIBUTE{{C.CKA_LABEL, nil, 0}}
	if err := o.getAttribute(attrs); err != nil {
		return "", err
	}
	n := attrs[0].ulValueLen

	cLabel := (*C.CK_UTF8CHAR)(C.malloc(C.ulong(n)))
	defer C.free(unsafe.Pointer(cLabel))
	attrs[0].pValue = C.CK_VOID_PTR(cLabel)

	if err := o.getAttribute(attrs); err != nil {
		return "", err
	}
	return ckGoString(cLabel, n), nil
}

// setLabel sets the label of the object overwriting any previous value.
func (o Object) setLabel(s string) error {
	cs, free := ckCString(s)
	defer free()

	attrs := []C.CK_ATTRIBUTE{{C.CKA_LABEL, C.CK_VOID_PTR(cs), C.CK_ULONG(len(s))}}
	return o.setAttribute(attrs)
}

// Certificate parses the underlying object as a certificate. If the object
// isn't a certificate, this method fails.
func (o Object) Certificate() (*Certificate, error) {
	if o.Class() != ClassCertificate {
		return nil, fmt.Errorf("object has class: %s", o.Class())
	}
	ct := (*C.CK_CERTIFICATE_TYPE)(C.malloc(C.sizeof_CK_CERTIFICATE_TYPE))
	defer C.free(unsafe.Pointer(ct))

	attrs := []C.CK_ATTRIBUTE{
		{C.CKA_CERTIFICATE_TYPE, C.CK_VOID_PTR(ct), C.CK_ULONG(C.sizeof_CK_CERTIFICATE_TYPE)},
	}
	if err := o.getAttribute(attrs); err != nil {
		return nil, fmt.Errorf("getting certificate type: %w", err)
	}
	return &Certificate{o, *ct}, nil
}

// PublicKey parses the underlying object as a public key. Both RSA and ECDSA
// keys are supported.
//
// If the object isn't a public key, this method fails.
func (o Object) PublicKey() (crypto.PublicKey, error) {
	if o.Class() != ClassPublicKey {
		return nil, fmt.Errorf("object has class: %s", o.Class())
	}

	kt := (*C.CK_KEY_TYPE)(C.malloc(C.sizeof_CK_KEY_TYPE))
	defer C.free(unsafe.Pointer(kt))

	attrs := []C.CK_ATTRIBUTE{
		{C.CKA_KEY_TYPE, C.CK_VOID_PTR(kt), C.CK_ULONG(C.sizeof_CK_KEY_TYPE)},
	}
	if err := o.getAttribute(attrs); err != nil {
		return nil, fmt.Errorf("getting certificate type: %w", err)
	}
	switch *kt {
	case C.CKK_EC:
		return o.ecdsaPublicKey()
	case C.CKK_RSA:
		return o.rsaPublicKey()
	default:
		return nil, fmt.Errorf("unsupported key type: 0x%x", *kt)
	}
}

func (o Object) rsaPublicKey() (crypto.PublicKey, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc399398838
	attrs := []C.CK_ATTRIBUTE{
		{C.CKA_MODULUS, nil, 0},
		{C.CKA_PUBLIC_EXPONENT, nil, 0},
	}
	if err := o.getAttribute(attrs); err != nil {
		return nil, fmt.Errorf("getting attributes: %w", err)
	}
	if attrs[0].ulValueLen == 0 {
		return nil, fmt.Errorf("no modulus attribute returned")
	}
	if attrs[1].ulValueLen == 0 {
		return nil, fmt.Errorf("no public exponent returned")
	}

	cN := (C.CK_VOID_PTR)(C.malloc(attrs[0].ulValueLen * C.sizeof_CK_BYTE))
	defer C.free(unsafe.Pointer(cN))
	attrs[0].pValue = cN

	cE := (C.CK_VOID_PTR)(C.malloc(attrs[1].ulValueLen))
	defer C.free(unsafe.Pointer(cE))
	attrs[1].pValue = cE

	if err := o.getAttribute(attrs); err != nil {
		return nil, fmt.Errorf("getting attribute values: %w", err)
	}

	nBytes := C.GoBytes(unsafe.Pointer(cN), C.int(attrs[0].ulValueLen))
	eBytes := C.GoBytes(unsafe.Pointer(cE), C.int(attrs[1].ulValueLen))

	var n, e big.Int
	n.SetBytes(nBytes)
	e.SetBytes(eBytes)
	return &rsa.PublicKey{N: &n, E: int(e.Int64())}, nil
}

func (o Object) ecdsaPublicKey() (crypto.PublicKey, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc399398881
	attrs := []C.CK_ATTRIBUTE{
		{C.CKA_EC_PARAMS, nil, 0},
		{C.CKA_EC_POINT, nil, 0},
	}
	if err := o.getAttribute(attrs); err != nil {
		return nil, fmt.Errorf("getting attributes: %w", err)
	}
	if attrs[0].ulValueLen == 0 {
		return nil, fmt.Errorf("no ec parameters available")
	}
	if attrs[1].ulValueLen == 0 {
		return nil, fmt.Errorf("no ec point available")
	}

	cParam := (C.CK_VOID_PTR)(C.malloc(attrs[0].ulValueLen))
	defer C.free(unsafe.Pointer(cParam))
	attrs[0].pValue = cParam

	cPoint := (C.CK_VOID_PTR)(C.malloc(attrs[1].ulValueLen))
	defer C.free(unsafe.Pointer(cPoint))
	attrs[1].pValue = cPoint

	if err := o.getAttribute(attrs); err != nil {
		return nil, fmt.Errorf("getting attribute values: %w", err)
	}

	paramBytes := C.GoBytes(unsafe.Pointer(cParam), C.int(attrs[0].ulValueLen))
	pointBytes := C.GoBytes(unsafe.Pointer(cPoint), C.int(attrs[1].ulValueLen))

	var curve elliptic.Curve
	if bytes.Equal(paramBytes, p256OIDRaw) {
		curve = elliptic.P256()
	} else if bytes.Equal(paramBytes, p384OIDRaw) {
		curve = elliptic.P384()
	} else if bytes.Equal(paramBytes, p521OIDRaw) {
		curve = elliptic.P521()
	} else {
		return nil, fmt.Errorf("unsupported curve")
	}

	var rawPoint asn1.RawValue
	if _, err := asn1.Unmarshal(pointBytes, &rawPoint); err != nil {
		return nil, fmt.Errorf("decoding ec point: %v", err)
	}
	x, y := elliptic.Unmarshal(curve, rawPoint.Bytes)
	if x == nil {
		return nil, fmt.Errorf("invalid point format")
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// PrivateKey parses the underlying object as a private key. Both RSA and ECDSA
// keys are supported.
//
// The returned PrivateKey implements crypto.Signer and optionally crypto.Decrypter
// depending on the supported mechanisms.
//
// If the object isn't a public key, this method fails.
func (o Object) PrivateKey(pub crypto.PublicKey) (crypto.PrivateKey, error) {
	if o.Class() != ClassPrivateKey {
		return nil, fmt.Errorf("object has class: %s", o.Class())
	}

	kt := (*C.CK_KEY_TYPE)(C.malloc(C.sizeof_CK_KEY_TYPE))
	defer C.free(unsafe.Pointer(kt))

	attrs := []C.CK_ATTRIBUTE{
		{C.CKA_KEY_TYPE, C.CK_VOID_PTR(kt), C.CK_ULONG(C.sizeof_CK_KEY_TYPE)},
	}
	if err := o.getAttribute(attrs); err != nil {
		return nil, fmt.Errorf("getting certificate type: %w", err)
	}
	switch *kt {
	case C.CKK_EC:
		p, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected ecdsa public key, got: %T", pub)
		}
		return &ecdsaPrivateKey{o, p}, nil
	case C.CKK_RSA:
		p, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected rsa public key, got: %T", pub)
		}
		return &rsaPrivateKey{o, p}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: 0x%x", *kt)
	}
}

// Precomputed ASN1 signature prefixes.
//
// Borrowed from crypto/rsa.
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

type rsaPrivateKey struct {
	o   Object
	pub *rsa.PublicKey
}

func (r *rsaPrivateKey) Public() crypto.PublicKey {
	return r.pub
}

func (r *rsaPrivateKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if o, ok := opts.(*rsa.PSSOptions); ok {
		return r.signPSS(digest, o)
	}

	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc399398842
	size := opts.HashFunc().Size()
	if size != len(digest) {
		return nil, fmt.Errorf("input must be hashed")
	}
	prefix, ok := hashPrefixes[opts.HashFunc()]
	if !ok {
		return nil, fmt.Errorf("unsupported hash function: %s", opts.HashFunc())
	}

	preAndDigest := append(prefix, digest...)
	cBytes := toCBytes(preAndDigest)

	cSig := make([]C.CK_BYTE, r.pub.Size())
	cSigLen := C.CK_ULONG(len(cSig))

	m := C.CK_MECHANISM{C.CKM_RSA_PKCS, nil, 0}
	rv := C.ck_sign_init(r.o.fl, r.o.h, &m, r.o.o)
	if err := isOk("C_SignInit", rv); err != nil {
		return nil, err
	}
	rv = C.ck_sign(r.o.fl, r.o.h, &cBytes[0], C.CK_ULONG(len(cBytes)), &cSig[0], &cSigLen)
	if err := isOk("C_Sign", rv); err != nil {
		return nil, err
	}

	if int(cSigLen) != len(cSig) {
		return nil, fmt.Errorf("expected signature of length %d, got %d", len(cSig), cSigLen)
	}
	sig := toBytes(cSig)
	return sig, nil
}

func (r *rsaPrivateKey) signPSS(digest []byte, opts *rsa.PSSOptions) ([]byte, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc399398846
	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc399398845
	cParam := (C.CK_RSA_PKCS_PSS_PARAMS_PTR)(C.malloc(C.sizeof_CK_RSA_PKCS_PSS_PARAMS))
	defer C.free(unsafe.Pointer(cParam))

	switch opts.Hash {
	case crypto.SHA256:
		cParam.hashAlg = C.CKM_SHA256
		cParam.mgf = C.CKG_MGF1_SHA256
	case crypto.SHA384:
		cParam.hashAlg = C.CKM_SHA384
		cParam.mgf = C.CKG_MGF1_SHA384
	case crypto.SHA512:
		cParam.hashAlg = C.CKM_SHA512
		cParam.mgf = C.CKG_MGF1_SHA512
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", opts.Hash)
	}

	switch opts.SaltLength {
	case rsa.PSSSaltLengthAuto:
		// Same logic as crypto/rsa.
		l := (r.pub.N.BitLen()-1+7)/8 - 2 - opts.Hash.Size()
		cParam.sLen = C.CK_ULONG(l)
	case rsa.PSSSaltLengthEqualsHash:
		cParam.sLen = C.CK_ULONG(opts.Hash.Size())
	default:
		cParam.sLen = C.CK_ULONG(opts.SaltLength)
	}

	cBytes := toCBytes(digest)

	cSig := make([]C.CK_BYTE, r.pub.Size())
	cSigLen := C.CK_ULONG(len(cSig))

	m := C.CK_MECHANISM{
		mechanism:      C.CKM_RSA_PKCS_PSS,
		pParameter:     C.CK_VOID_PTR(cParam),
		ulParameterLen: C.CK_ULONG(C.sizeof_CK_RSA_PKCS_PSS_PARAMS),
	}

	rv := C.ck_sign_init(r.o.fl, r.o.h, &m, r.o.o)
	if err := isOk("C_SignInit", rv); err != nil {
		return nil, err
	}
	rv = C.ck_sign(r.o.fl, r.o.h, &cBytes[0], C.CK_ULONG(len(cBytes)), &cSig[0], &cSigLen)
	if err := isOk("C_Sign", rv); err != nil {
		return nil, err
	}

	if int(cSigLen) != len(cSig) {
		return nil, fmt.Errorf("expected signature of length %d, got %d", len(cSig), cSigLen)
	}
	sig := toBytes(cSig)
	return sig, nil
}

type ecdsaPrivateKey struct {
	o   Object
	pub *ecdsa.PublicKey
}

func (e *ecdsaPrivateKey) Public() crypto.PublicKey {
	return e.pub
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (e *ecdsaPrivateKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc399398884
	m := C.CK_MECHANISM{C.CKM_ECDSA, nil, 0}
	rv := C.ck_sign_init(e.o.fl, e.o.h, &m, e.o.o)
	if err := isOk("C_SignInit", rv); err != nil {
		return nil, err
	}

	byteLen := (e.pub.Curve.Params().BitSize + 7) / 8
	cSig := make([]C.CK_BYTE, byteLen*2)
	cSigLen := C.CK_ULONG(len(cSig))

	cBytes := toCBytes(digest)

	rv = C.ck_sign(e.o.fl, e.o.h, &cBytes[0], C.CK_ULONG(len(digest)), &cSig[0], &cSigLen)
	if err := isOk("C_Sign", rv); err != nil {
		return nil, err
	}

	if int(cSigLen) != len(cSig) {
		return nil, fmt.Errorf("expected signature of length %d, got %d", len(cSig), cSigLen)
	}
	sig := toBytes(cSig)

	var (
		r = big.NewInt(0)
		s = big.NewInt(0)
	)
	r.SetBytes(sig[:len(sig)/2])
	s.SetBytes(sig[len(sig)/2:])

	return asn1.Marshal(ecdsaSignature{r, s})
}

// CertificateType determines the kind of certificate a certificate object holds.
// This can be X.509, WTLS, GPG, etc.
//
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959709
type CertificateType int

// Certificate types supported by this package.
const (
	CertificateX509 CertificateType = iota + 1
	CertificateUnknown
)

// Certificate holds a certificate object. Because certificates object can hold
// various kinds of certificates, callers should check the type before calling
// methods that parse the certificate.
//
//	cert, err := obj.Certificate()
//	if err != nil {
//		// ...
//	}
//	if cert.Type() != pkcs11.CertificateX509 {
//		// unexpected kind of certificate ...
//	}
//	x509Cert, err := cert.X509()
type Certificate struct {
	o Object
	t C.CK_CERTIFICATE_TYPE
}

// Type returns the format of the underlying certificate.
func (c *Certificate) Type() CertificateType {
	switch c.t {
	case C.CKC_X_509:
		return CertificateX509
	default:
		return CertificateUnknown
	}
}

// X509 parses the underlying certificate as an X.509 certificate.
//
// If the certificate holds a different type of certificate, this method
// returns an error.
func (c *Certificate) X509() (*x509.Certificate, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959712
	if c.t != C.CKC_X_509 {
		return nil, fmt.Errorf("invalid certificate type")
	}

	// TODO(ericchiang): Do we want to support CKA_URL?
	var n C.CK_ULONG
	attrs := []C.CK_ATTRIBUTE{
		{C.CKA_VALUE, nil, n},
	}
	if err := c.o.getAttribute(attrs); err != nil {
		return nil, fmt.Errorf("getting certificate type: %w", err)
	}
	n = attrs[0].ulValueLen
	if n == 0 {
		return nil, fmt.Errorf("certificate value not present")
	}
	cRaw := (C.CK_VOID_PTR)(C.malloc(C.ulong(n)))
	defer C.free(unsafe.Pointer(cRaw))

	attrs[0].pValue = cRaw
	if err := c.o.getAttribute(attrs); err != nil {
		return nil, fmt.Errorf("getting certificate type: %w", err)
	}

	raw := C.GoBytes(unsafe.Pointer(cRaw), C.int(n))
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %v", err)
	}
	return cert, nil
}

// keyOptions holds parameters used for generating a private key.
type keyOptions struct {
	// RSABits indicates that the generated key should be a RSA key and also
	// provides the number of bits.
	RSABits int
	// ECDSACurve indicates that the generated key should be an ECDSA key and
	// identifies the curve used to generate the key.
	ECDSACurve elliptic.Curve

	// Label for the final object.
	LabelPublic  string
	LabelPrivate string
}

// https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1.1

// Generate a private key on the slot, creating associated private and public
// key objects.
func (s *Slot) generate(opts keyOptions) (crypto.PrivateKey, error) {
	if opts.ECDSACurve != nil && opts.RSABits != 0 {
		return nil, fmt.Errorf("conflicting key parameters provided")
	}
	if opts.ECDSACurve != nil {
		return s.generateECDSA(opts)
	}
	if opts.RSABits != 0 {
		return s.generateRSA(opts)
	}
	return nil, fmt.Errorf("no key parameters provided")
}

// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959719
// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_Toc416959971
func (s *Slot) generateRSA(o keyOptions) (crypto.PrivateKey, error) {
	var (
		mechanism = C.CK_MECHANISM{
			mechanism: C.CKM_RSA_PKCS_KEY_PAIR_GEN,
		}
		pubH  C.CK_OBJECT_HANDLE
		privH C.CK_OBJECT_HANDLE
	)

	cTrue := (C.CK_VOID_PTR)(C.malloc(C.sizeof_CK_BBOOL))
	cFalse := (C.CK_VOID_PTR)(C.malloc(C.sizeof_CK_BBOOL))
	defer C.free(unsafe.Pointer(cTrue))
	defer C.free(unsafe.Pointer(cFalse))
	*((*C.CK_BBOOL)(cTrue)) = C.CK_TRUE
	*((*C.CK_BBOOL)(cFalse)) = C.CK_FALSE

	cModBits := (C.CK_VOID_PTR)(C.malloc(C.sizeof_CK_ULONG))
	defer C.free(unsafe.Pointer(cModBits))

	*((*C.CK_ULONG)(cModBits)) = C.CK_ULONG(o.RSABits)

	privTmpl := []C.CK_ATTRIBUTE{
		{C.CKA_PRIVATE, cTrue, C.CK_ULONG(C.sizeof_CK_BBOOL)},
		{C.CKA_SENSITIVE, cTrue, C.CK_ULONG(C.sizeof_CK_BBOOL)},
		{C.CKA_SIGN, cTrue, C.CK_ULONG(C.sizeof_CK_BBOOL)},
	}

	if o.LabelPrivate != "" {
		cs, free := ckCString(o.LabelPrivate)
		defer free()

		privTmpl = append(privTmpl, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(cs),
			C.CK_ULONG(len(o.LabelPrivate)),
		})
	}

	pubTmpl := []C.CK_ATTRIBUTE{
		{C.CKA_MODULUS_BITS, cModBits, C.CK_ULONG(C.sizeof_CK_ULONG)},
		{C.CKA_VERIFY, cTrue, C.CK_ULONG(C.sizeof_CK_BBOOL)},
	}

	if o.LabelPublic != "" {
		cs, free := ckCString(o.LabelPublic)
		defer free()

		pubTmpl = append(pubTmpl, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(cs),
			C.CK_ULONG(len(o.LabelPublic)),
		})
	}

	rv := C.ck_generate_key_pair(
		s.fl, s.h, &mechanism,
		&pubTmpl[0], C.CK_ULONG(len(pubTmpl)),
		&privTmpl[0], C.CK_ULONG(len(privTmpl)),
		&pubH, &privH,
	)

	if err := isOk("C_GenerateKeyPair", rv); err != nil {
		return nil, err
	}

	pubObj, err := s.newObject(pubH)
	if err != nil {
		return nil, fmt.Errorf("public key object: %w", err)
	}
	privObj, err := s.newObject(privH)
	if err != nil {
		return nil, fmt.Errorf("private key object: %w", err)
	}
	pub, err := pubObj.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	priv, err := privObj.PrivateKey(pub)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	return priv, nil
}

// https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1.1
//
// Generated with https://play.golang.org/p/tkqXov5Xpwp
var (
	p256OIDRaw = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	p384OIDRaw = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}
	p521OIDRaw = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23}
)

// generateECDSA implements the CKM_ECDSA_KEY_PAIR_GEN mechanism.
//
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959719
// https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1.1
// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_Toc416960014
func (s *Slot) generateECDSA(o keyOptions) (crypto.PrivateKey, error) {
	var (
		mechanism = C.CK_MECHANISM{
			mechanism: C.CKM_EC_KEY_PAIR_GEN,
		}
		pubH  C.CK_OBJECT_HANDLE
		privH C.CK_OBJECT_HANDLE
	)

	if o.ECDSACurve == nil {
		return nil, fmt.Errorf("no curve provided")
	}

	var oid []byte
	switch o.ECDSACurve.Params().Name {
	case "P-256":
		oid = p256OIDRaw
	case "P-384":
		oid = p384OIDRaw
	case "P-521":
		oid = p521OIDRaw
	default:
		return nil, fmt.Errorf("unsupported ECDSA curve")
	}

	// When passing a struct or array to C, that value can't refer to Go
	// memory. Allocate all attribute values in C rather than in Go.
	cOID := (C.CK_VOID_PTR)(C.CBytes(oid))
	defer C.free(unsafe.Pointer(cOID))

	cTrue := (C.CK_VOID_PTR)(C.malloc(C.sizeof_CK_BBOOL))
	cFalse := (C.CK_VOID_PTR)(C.malloc(C.sizeof_CK_BBOOL))
	defer C.free(unsafe.Pointer(cTrue))
	defer C.free(unsafe.Pointer(cFalse))
	*((*C.CK_BBOOL)(cTrue)) = C.CK_TRUE
	*((*C.CK_BBOOL)(cFalse)) = C.CK_FALSE

	privTmpl := []C.CK_ATTRIBUTE{
		{C.CKA_PRIVATE, cTrue, C.CK_ULONG(C.sizeof_CK_BBOOL)},
		{C.CKA_SENSITIVE, cTrue, C.CK_ULONG(C.sizeof_CK_BBOOL)},
		{C.CKA_SIGN, cTrue, C.CK_ULONG(C.sizeof_CK_BBOOL)},
	}

	if o.LabelPrivate != "" {
		cs, free := ckCString(o.LabelPrivate)
		defer free()

		privTmpl = append(privTmpl, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(cs),
			C.CK_ULONG(len(o.LabelPrivate)),
		})
	}

	pubTmpl := []C.CK_ATTRIBUTE{
		{C.CKA_EC_PARAMS, cOID, C.CK_ULONG(len(oid))},
		{C.CKA_VERIFY, cTrue, C.CK_ULONG(C.sizeof_CK_BBOOL)},
	}
	if o.LabelPublic != "" {
		cs, free := ckCString(o.LabelPublic)
		defer free()

		pubTmpl = append(pubTmpl, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(cs),
			C.CK_ULONG(len(o.LabelPublic)),
		})
	}

	rv := C.ck_generate_key_pair(
		s.fl, s.h, &mechanism,
		&pubTmpl[0], C.CK_ULONG(len(pubTmpl)),
		&privTmpl[0], C.CK_ULONG(len(privTmpl)),
		&pubH, &privH,
	)

	if err := isOk("C_GenerateKeyPair", rv); err != nil {
		return nil, err
	}

	pubObj, err := s.newObject(pubH)
	if err != nil {
		return nil, fmt.Errorf("public key object: %w", err)
	}
	privObj, err := s.newObject(privH)
	if err != nil {
		return nil, fmt.Errorf("private key object: %w", err)
	}
	pub, err := pubObj.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	priv, err := privObj.PrivateKey(pub)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	return priv, nil
}

func (r *rsaPrivateKey) Decrypt(_ io.Reader, encryptedData []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	var m C.CK_MECHANISM

	if o, ok := opts.(*rsa.OAEPOptions); ok {
		cParam := (C.CK_RSA_PKCS_OAEP_PARAMS_PTR)(C.malloc(C.sizeof_CK_RSA_PKCS_OAEP_PARAMS))
		defer C.free(unsafe.Pointer(cParam))

		switch o.Hash {
		case crypto.SHA256:
			cParam.hashAlg = C.CKM_SHA256
			cParam.mgf = C.CKG_MGF1_SHA256
		case crypto.SHA384:
			cParam.hashAlg = C.CKM_SHA384
			cParam.mgf = C.CKG_MGF1_SHA384
		case crypto.SHA512:
			cParam.hashAlg = C.CKM_SHA512
			cParam.mgf = C.CKG_MGF1_SHA512
		case crypto.SHA1:
			cParam.hashAlg = C.CKM_SHA_1
			cParam.mgf = C.CKG_MGF1_SHA1
		default:
			return nil, fmt.Errorf("decryptOAEP error, unsupported hash algorithm: %s", o.Hash)
		}

		cParam.source = C.CKZ_DATA_SPECIFIED
		cParam.pSourceData = nil
		cParam.ulSourceDataLen = 0

		m = C.CK_MECHANISM{
			mechanism:      C.CKM_RSA_PKCS_OAEP,
			pParameter:     C.CK_VOID_PTR(cParam),
			ulParameterLen: C.CK_ULONG(C.sizeof_CK_RSA_PKCS_OAEP_PARAMS),
		}
	} else {
		m = C.CK_MECHANISM{C.CKM_RSA_PKCS, nil, 0}
	}

	cEncDataBytes := toCBytes(encryptedData)

	rv := C.ck_decrypt_init(r.o.fl, r.o.h, &m, r.o.o)
	if err := isOk("C_DecryptInit", rv); err != nil {
		return nil, err
	}

	var cDecryptedLen C.CK_ULONG

	// First call is used to determine length necessary to hold decrypted data (PKCS #11 5.2)
	rv = C.ck_decrypt(r.o.fl, r.o.h, &cEncDataBytes[0], C.CK_ULONG(len(cEncDataBytes)), nil, &cDecryptedLen)
	if err := isOk("C_Decrypt", rv); err != nil {
		return nil, err
	}

	cDecrypted := make([]C.CK_BYTE, cDecryptedLen)

	rv = C.ck_decrypt(r.o.fl, r.o.h, &cEncDataBytes[0], C.CK_ULONG(len(cEncDataBytes)), &cDecrypted[0], &cDecryptedLen)
	if err := isOk("C_Decrypt", rv); err != nil {
		return nil, err
	}

	decrypted := toBytes(cDecrypted)

	// Removes null padding (PKCS#11 5.2): http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959738
	decrypted = bytes.Trim(decrypted, "\x00")

	return decrypted, nil
}

func toBytes(data []C.CK_BYTE) []byte {
	goBytes := make([]byte, len(data))
	for i, b := range data {
		goBytes[i] = byte(b)
	}
	return goBytes
}

func toCBytes(data []byte) []C.CK_BYTE {
	cBytes := make([]C.CK_BYTE, len(data))
	for i, b := range data {
		cBytes[i] = C.CK_BYTE(b)
	}
	return cBytes
}
