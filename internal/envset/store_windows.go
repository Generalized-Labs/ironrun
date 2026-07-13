//go:build windows

package envset

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type nativeStore struct{}
type credential struct {
	Flags, Type                                                                                                  uint32
	TargetName, Comment, LastWritten, CredentialBlob, Persist, AttributeCount, Attributes, TargetAlias, UserName uintptr
	CredentialBlobSize                                                                                           uint32
}

var advapi = windows.NewLazySystemDLL("advapi32.dll")

func newNativeStore() (ValueStore, error) { return nativeStore{}, nil }
func (nativeStore) Name() string          { return "Windows Credential Manager" }
func target(scope, key string) string     { return "ironrun/" + scope + "/" + key }
func (nativeStore) Set(scope, key, value string) error {
	if err := validateName(key); err != nil {
		return err
	}
	name, _ := windows.UTF16PtrFromString(target(scope, key))
	user, _ := windows.UTF16PtrFromString("ironrun")
	blob := []byte(value)
	c := credential{Type: 1, TargetName: uintptr(unsafe.Pointer(name)), CredentialBlob: uintptr(unsafe.Pointer(&blob[0])), CredentialBlobSize: uint32(len(blob)), Persist: 2, UserName: uintptr(unsafe.Pointer(user))}
	r, _, e := advapi.NewProc("CredWriteW").Call(uintptr(unsafe.Pointer(&c)), 0)
	if r == 0 {
		return fmt.Errorf("credential manager write failed: %w", e)
	}
	return nil
}
func (nativeStore) Get(scope, key string) (string, error) {
	name, _ := windows.UTF16PtrFromString(target(scope, key))
	var p *credential
	r, _, _ := advapi.NewProc("CredReadW").Call(uintptr(unsafe.Pointer(name)), 1, 0, uintptr(unsafe.Pointer(&p)))
	if r == 0 || p == nil {
		return "", ErrMissing
	}
	defer advapi.NewProc("CredFree").Call(uintptr(unsafe.Pointer(p)))
	b := unsafe.Slice((*byte)(unsafe.Pointer(p.CredentialBlob)), p.CredentialBlobSize)
	return string(b), nil
}
func (nativeStore) Delete(scope, key string) error {
	name, _ := windows.UTF16PtrFromString(target(scope, key))
	r, _, e := advapi.NewProc("CredDeleteW").Call(uintptr(unsafe.Pointer(name)), 1, 0)
	if r == 0 && e != syscall.Errno(1168) {
		return fmt.Errorf("credential manager delete failed: %w", e)
	}
	return nil
}
func (nativeStore) DeleteScope(scope string) error { return nil }
