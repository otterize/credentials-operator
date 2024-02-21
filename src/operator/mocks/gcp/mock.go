package mock_gcp

import (
	gomock "go.uber.org/mock/gomock"
	"reflect"
)

type MockGCPServiceAccountManager struct {
	ctrl     *gomock.Controller
	recorder *MockGCPServiceAccountManagerRecorder
}

type MockGCPServiceAccountManagerRecorder struct {
	mock *MockGCPServiceAccountManager
}

func NewMockGCPServiceAccountManager(ctrl *gomock.Controller) *MockGCPServiceAccountManager {
	mock := &MockGCPServiceAccountManager{ctrl: ctrl}
	mock.recorder = &MockGCPServiceAccountManagerRecorder{mock}
	return mock
}

func (m *MockGCPServiceAccountManager) EXPECT() *MockGCPServiceAccountManagerRecorder {
	return m.recorder
}

func (m *MockGCPServiceAccountManager) GetGSAFullName(namespace string, name string) string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGSAFullName", namespace, name)
	ret0, _ := ret[0].(string)
	return ret0
}

func (mr *MockGCPServiceAccountManagerRecorder) GetGSAFullName(namespace string, name string) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	reflection := reflect.TypeOf((*MockGCPServiceAccountManager)(nil).GetGSAFullName)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGSAFullName", reflection, namespace, name)
}
