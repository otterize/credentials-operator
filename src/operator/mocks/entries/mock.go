// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/otterize/spire-integration-operator/src/controllers (interfaces: WorkloadRegistry)

// Package mock_entries is a generated GoMock package.
package mock_entries

import (
	context "context"
	reflect "reflect"

	goset "github.com/amit7itz/goset"
	gomock "github.com/golang/mock/gomock"
)

// MockWorkloadRegistry is a mock of WorkloadRegistry interface.
type MockWorkloadRegistry struct {
	ctrl     *gomock.Controller
	recorder *MockWorkloadRegistryMockRecorder
}

// MockWorkloadRegistryMockRecorder is the mock recorder for MockWorkloadRegistry.
type MockWorkloadRegistryMockRecorder struct {
	mock *MockWorkloadRegistry
}

// NewMockWorkloadRegistry creates a new mock instance.
func NewMockWorkloadRegistry(ctrl *gomock.Controller) *MockWorkloadRegistry {
	mock := &MockWorkloadRegistry{ctrl: ctrl}
	mock.recorder = &MockWorkloadRegistryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockWorkloadRegistry) EXPECT() *MockWorkloadRegistryMockRecorder {
	return m.recorder
}

// CleanupOrphanK8SPodEntries mocks base method.
func (m *MockWorkloadRegistry) CleanupOrphanK8SPodEntries(arg0 context.Context, arg1 string, arg2 map[string]*goset.Set[string]) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CleanupOrphanK8SPodEntries", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// CleanupOrphanK8SPodEntries indicates an expected call of CleanupOrphanK8SPodEntries.
func (mr *MockWorkloadRegistryMockRecorder) CleanupOrphanK8SPodEntries(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CleanupOrphanK8SPodEntries", reflect.TypeOf((*MockWorkloadRegistry)(nil).CleanupOrphanK8SPodEntries), arg0, arg1, arg2)
}

// RegisterK8SPod mocks base method.
func (m *MockWorkloadRegistry) RegisterK8SPod(arg0 context.Context, arg1, arg2, arg3 string, arg4 int32, arg5 []string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RegisterK8SPod", arg0, arg1, arg2, arg3, arg4, arg5)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RegisterK8SPod indicates an expected call of RegisterK8SPod.
func (mr *MockWorkloadRegistryMockRecorder) RegisterK8SPod(arg0, arg1, arg2, arg3, arg4, arg5 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterK8SPod", reflect.TypeOf((*MockWorkloadRegistry)(nil).RegisterK8SPod), arg0, arg1, arg2, arg3, arg4, arg5)
}