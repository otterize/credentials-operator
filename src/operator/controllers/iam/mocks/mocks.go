// Code generated by MockGen. DO NOT EDIT.
// Source: agent.go

// Package mock_iam is a generated GoMock package.
package mock_iam

import (
	context "context"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
)

// MockIAMCredentialsAgent is a mock of IAMCredentialsAgent interface.
type MockIAMCredentialsAgent struct {
	ctrl     *gomock.Controller
	recorder *MockIAMCredentialsAgentMockRecorder
}

// MockIAMCredentialsAgentMockRecorder is the mock recorder for MockIAMCredentialsAgent.
type MockIAMCredentialsAgentMockRecorder struct {
	mock *MockIAMCredentialsAgent
}

// NewMockIAMCredentialsAgent creates a new mock instance.
func NewMockIAMCredentialsAgent(ctrl *gomock.Controller) *MockIAMCredentialsAgent {
	mock := &MockIAMCredentialsAgent{ctrl: ctrl}
	mock.recorder = &MockIAMCredentialsAgentMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIAMCredentialsAgent) EXPECT() *MockIAMCredentialsAgentMockRecorder {
	return m.recorder
}

// OnPodAdmission mocks base method.
func (m *MockIAMCredentialsAgent) OnPodAdmission(ctx context.Context, pod *v1.Pod, serviceAccount *v1.ServiceAccount) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OnPodAdmission", ctx, pod, serviceAccount)
	ret0, _ := ret[0].(error)
	return ret0
}

// OnPodAdmission indicates an expected call of OnPodAdmission.
func (mr *MockIAMCredentialsAgentMockRecorder) OnPodAdmission(ctx, pod, serviceAccount interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnPodAdmission", reflect.TypeOf((*MockIAMCredentialsAgent)(nil).OnPodAdmission), ctx, pod, serviceAccount)
}

// ApplyOnPodLabel mocks base method.
func (m *MockIAMCredentialsAgent) ApplyOnPodLabel() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ApplyOnPodLabel")
	ret0, _ := ret[0].(string)
	return ret0
}

// ApplyOnPodLabel indicates an expected call of ApplyOnPodLabel.
func (mr *MockIAMCredentialsAgentMockRecorder) ApplyOnPodLabel() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ApplyOnPodLabel", reflect.TypeOf((*MockIAMCredentialsAgent)(nil).ApplyOnPodLabel))
}

// DeleteServiceIAMRole mocks base method.
func (m *MockIAMCredentialsAgent) DeleteServiceIAMRole(ctx context.Context, namespace, name string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteServiceIAMRole", ctx, namespace, name)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteServiceIAMRole indicates an expected call of DeleteServiceIAMRole.
func (mr *MockIAMCredentialsAgentMockRecorder) DeleteServiceIAMRole(ctx, namespace, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteServiceIAMRole", reflect.TypeOf((*MockIAMCredentialsAgent)(nil).DeleteServiceIAMRole), ctx, namespace, name)
}

// ReconcileServiceIAMRole mocks base method.
func (m *MockIAMCredentialsAgent) ReconcileServiceIAMRole(ctx context.Context, serviceAccount *v1.ServiceAccount) (bool, bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReconcileServiceIAMRole", ctx, serviceAccount)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(bool)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ReconcileServiceIAMRole indicates an expected call of ReconcileServiceIAMRole.
func (mr *MockIAMCredentialsAgentMockRecorder) ReconcileServiceIAMRole(ctx, serviceAccount interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReconcileServiceIAMRole", reflect.TypeOf((*MockIAMCredentialsAgent)(nil).ReconcileServiceIAMRole), ctx, serviceAccount)
}
