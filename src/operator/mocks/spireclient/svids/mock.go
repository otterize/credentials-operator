// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/otterize/spire-integration-operator/src/controllers/spireclient/svids (interfaces: Store)

// Package mock_svids is a generated GoMock package.
package mock_svids

import (
	context "context"
	crypto "crypto"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	svids "github.com/otterize/spire-integration-operator/src/controllers/spireclient/svids"
)

// MockStore is a mock of Store interface.
type MockStore struct {
	ctrl     *gomock.Controller
	recorder *MockStoreMockRecorder
}

// MockStoreMockRecorder is the mock recorder for MockStore.
type MockStoreMockRecorder struct {
	mock *MockStore
}

// NewMockStore creates a new mock instance.
func NewMockStore(ctrl *gomock.Controller) *MockStore {
	mock := &MockStore{ctrl: ctrl}
	mock.recorder = &MockStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStore) EXPECT() *MockStoreMockRecorder {
	return m.recorder
}

// GeneratePrivateKey mocks base method.
func (m *MockStore) GeneratePrivateKey() (crypto.PrivateKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GeneratePrivateKey")
	ret0, _ := ret[0].(crypto.PrivateKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GeneratePrivateKey indicates an expected call of GeneratePrivateKey.
func (mr *MockStoreMockRecorder) GeneratePrivateKey() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GeneratePrivateKey", reflect.TypeOf((*MockStore)(nil).GeneratePrivateKey))
}

// GetX509SVID mocks base method.
func (m *MockStore) GetX509SVID(arg0 context.Context, arg1 string, arg2 crypto.PrivateKey) (svids.EncodedX509SVID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetX509SVID", arg0, arg1, arg2)
	ret0, _ := ret[0].(svids.EncodedX509SVID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetX509SVID indicates an expected call of GetX509SVID.
func (mr *MockStoreMockRecorder) GetX509SVID(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetX509SVID", reflect.TypeOf((*MockStore)(nil).GetX509SVID), arg0, arg1, arg2)
}
