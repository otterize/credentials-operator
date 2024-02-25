package mock_gcp

import (
	"context"
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

// GetGSAFullName mocks base method.
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

// DeleteGSA mocks base method.
func (m *MockGCPServiceAccountManager) DeleteGSA(ctx context.Context, namespaceName string, ksaName string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteGSA", ctx, namespaceName, ksaName)
	ret0, _ := ret[0].(error)
	return ret0
}
func (mr *MockGCPServiceAccountManagerRecorder) DeleteGSA(ctx context.Context, namespaceName string, ksaName string) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	reflection := reflect.TypeOf((*MockGCPServiceAccountManager)(nil).DeleteGSA)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteGSA", reflection, ctx, namespaceName, ksaName)
}

// CreateAndConnectGSA mocks base method.
func (m *MockGCPServiceAccountManager) CreateAndConnectGSA(ctx context.Context, namespaceName string, ksaName string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAndConnectGSA", ctx, namespaceName, ksaName)
	ret0, _ := ret[0].(error)
	return ret0
}
func (mr *MockGCPServiceAccountManagerRecorder) CreateAndConnectGSA(ctx context.Context, namespaceName string, ksaName string) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	reflection := reflect.TypeOf((*MockGCPServiceAccountManager)(nil).CreateAndConnectGSA)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAndConnectGSA", reflection, ctx, namespaceName, ksaName)
}

// AnnotateGKENamespace mocks base method.
func (m *MockGCPServiceAccountManager) AnnotateGKENamespace(ctx context.Context, namespaceName string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AnnotateGKENamespace", ctx, namespaceName)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[0].(error)
	return ret0, ret1
}
func (mr *MockGCPServiceAccountManagerRecorder) AnnotateGKENamespace(ctx context.Context, namespaceName string) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	reflection := reflect.TypeOf((*MockGCPServiceAccountManager)(nil).AnnotateGKENamespace)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AnnotateGKENamespace", reflection, ctx, namespaceName)
}
