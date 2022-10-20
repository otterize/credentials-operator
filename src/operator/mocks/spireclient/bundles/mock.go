// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/otterize/spire-integration-operator/src/spireclient/bundles (interfaces: Store)

// Package mock_bundles is a generated GoMock package.
package mock_bundles

import (
	context "context"
	"github.com/otterize/spire-integration-operator/src/operator/controllers/spireclient/bundles"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
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

// GetTrustBundle mocks base method.
func (m *MockStore) GetTrustBundle(arg0 context.Context) (bundles.EncodedTrustBundle, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTrustBundle", arg0)
	ret0, _ := ret[0].(bundles.EncodedTrustBundle)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTrustBundle indicates an expected call of GetTrustBundle.
func (mr *MockStoreMockRecorder) GetTrustBundle(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTrustBundle", reflect.TypeOf((*MockStore)(nil).GetTrustBundle), arg0)
}
