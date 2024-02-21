package main

import (
	"context"
	"testing"

	mock_pb "authentication/mocks"
	pb "authentication/proto"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

type UserClient struct {
	client pb.UserServiceClient
}

func NewUserClient(addr string) (*UserClient, error) {
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	return &UserClient{
		client: pb.NewUserServiceClient(conn),
	}, nil
}

func NewMockUserClient(ctrl *gomock.Controller) *UserClient {
	mockClient := mock_pb.NewMockUserServiceClient(ctrl)
	return &UserClient{
		client: mockClient,
	}
}

func TestAuthenticateUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := NewMockUserClient(ctrl)

	username := "testuser"
	password := "testpassword"
	ctx := context.Background()
	req := &pb.AuthenticationRequest{Username: username, Password: password}
	mockResp := &pb.AuthenticationResponse{Token: "mocked_token"}

	mockClient.client.(*mock_pb.MockUserServiceClient).
		EXPECT().
		AuthenticateUser(ctx, req).
		Return(mockResp, nil).
		Times(1)

	resp, err := mockClient.client.AuthenticateUser(ctx, req)

	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, mockResp, resp)
}

func TestGetUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := NewMockUserClient(ctrl)

	ctx := context.Background()
	req := &pb.UserDetailsRequest{Token: "mocked_token"}
	mockResp := &pb.UserDetailsResponse{Name: "testuser", Age: 21}

	mockClient.client.(*mock_pb.MockUserServiceClient).
		EXPECT().
		GetUserDetails(ctx, req).
		Return(mockResp, nil).
		Times(1)

	resp, err := mockClient.client.GetUserDetails(ctx, req)

	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, mockResp, resp)
}
