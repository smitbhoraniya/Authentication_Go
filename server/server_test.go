package main

import (
	"context"
	"testing"

	pb "authentication/proto"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

func TestUserService_AuthenticateUser_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	server := userServiceServer{db: db}

	mock.ExpectExec("INSERT INTO users").
		WithArgs("testuser", "testpassword", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	resp, err := server.AuthenticateUser(context.Background(), &pb.AuthenticationRequest{
		Username: "testuser",
		Password: "testpassword",
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserService_SaveUserDetails_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	server := userServiceServer{db: db}

	mock.ExpectExec("UPDATE users").
		WithArgs("testname", 30, "testtoken").
		WillReturnResult(sqlmock.NewResult(0, 1))

	resp, err := server.SaveUserDetails(context.Background(), &pb.SaveUserDetailRequest{
		Name:  "testname",
		Age:   30,
		Token: "testtoken",
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserService_UpdateUserName_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	server := userServiceServer{db: db}

	mock.ExpectExec("UPDATE users").
		WithArgs("newname", "testtoken").
		WillReturnResult(sqlmock.NewResult(0, 1))

	resp, err := server.UpdateUserName(context.Background(), &pb.UpdateUserNameRequest{
		NewName: "newname",
		Token:   "testtoken",
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserService_GetUserDetails_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	server := userServiceServer{db: db}

	mock.ExpectQuery("SELECT name, age FROM users WHERE token = ?").
		WithArgs("testtoken").
		WillReturnRows(sqlmock.NewRows([]string{"name", "age"}).AddRow("testname", 30))

	resp, err := server.GetUserDetails(context.Background(), &pb.UserDetailsRequest{
		Token: "testtoken",
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "testname", resp.Name)
	assert.Equal(t, int32(30), resp.Age)

	assert.NoError(t, mock.ExpectationsWereMet())
}
