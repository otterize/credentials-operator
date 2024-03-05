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

// AppliesOnPod mocks base method.
func (m *MockIAMCredentialsAgent) AppliesOnPod(pod *v1.Pod) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AppliesOnPod", pod)
	ret0, _ := ret[0].(bool)
	return ret0
}

// AppliesOnPod indicates an expected call of AppliesOnPod.
func (mr *MockIAMCredentialsAgentMockRecorder) AppliesOnPod(pod interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AppliesOnPod", reflect.TypeOf((*MockIAMCredentialsAgent)(nil).AppliesOnPod), pod)
}

// OnPodAdmission mocks base method.
func (m *MockIAMCredentialsAgent) OnPodAdmission(pod *v1.Pod, serviceAccount *v1.ServiceAccount) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OnPodAdmission", pod, serviceAccount)
	ret0, _ := ret[0].(bool)
	return ret0
}

// OnPodAdmission indicates an expected call of OnPodAdmission.
func (mr *MockIAMCredentialsAgentMockRecorder) OnPodAdmission(pod, serviceAccount interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnPodAdmission", reflect.TypeOf((*MockIAMCredentialsAgent)(nil).OnPodAdmission), pod, serviceAccount)
}

// OnServiceAccountTermination mocks base method.
func (m *MockIAMCredentialsAgent) OnServiceAccountTermination(ctx context.Context, serviceAccount *v1.ServiceAccount) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OnServiceAccountTermination", ctx, serviceAccount)
	ret0, _ := ret[0].(error)
	return ret0
}

// OnServiceAccountTermination indicates an expected call of OnServiceAccountTermination.
func (mr *MockIAMCredentialsAgentMockRecorder) OnServiceAccountTermination(ctx, serviceAccount interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnServiceAccountTermination", reflect.TypeOf((*MockIAMCredentialsAgent)(nil).OnServiceAccountTermination), ctx, serviceAccount)
}

// OnServiceAccountUpdate mocks base method.
func (m *MockIAMCredentialsAgent) OnServiceAccountUpdate(ctx context.Context, serviceAccount *v1.ServiceAccount) (bool, bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OnServiceAccountUpdate", ctx, serviceAccount)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(bool)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// OnServiceAccountUpdate indicates an expected call of OnServiceAccountUpdate.
func (mr *MockIAMCredentialsAgentMockRecorder) OnServiceAccountUpdate(ctx, serviceAccount interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnServiceAccountUpdate", reflect.TypeOf((*MockIAMCredentialsAgent)(nil).OnServiceAccountUpdate), ctx, serviceAccount)
}
