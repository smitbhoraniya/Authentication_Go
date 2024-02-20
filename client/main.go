package main

import (
	"flag"
	"log"
	"net/http"
	"strings"

	pb "authentication/proto"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	addr = flag.String("addr", "localhost:50051", "the address to connect to")
)

type User struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Password string `json:"password"`
	Age      int32  `json:"age"`
	Token    string `json:"token"`
}

func main() {
	flag.Parse()
	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))

	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}

	defer conn.Close()
	client := pb.NewUserServiceClient(conn)

	r := gin.Default()
	r.POST("/user", func(ctx *gin.Context) {
		var user User

		err := ctx.ShouldBind(&user)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		res, err := client.AuthenticateUser(ctx, &pb.AuthenticationRequest{
			Username: user.Username,
			Password: user.Password,
		})
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		ctx.JSON(http.StatusCreated, gin.H{
			"token": res.Token,
		})
	})
	r.GET("/user", func(ctx *gin.Context) {
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization token is missing",
			})
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		res, err := client.GetUserDetails(ctx, &pb.UserDetailsRequest{
			Token: token,
		})
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{
			"username": res.Name,
			"age":      res.Age,
		})
	})
	r.PUT("/user", func(ctx *gin.Context) {
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization token is missing",
			})
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		var user User
		err := ctx.ShouldBind(&user)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		res, err := client.SaveUserDetails(ctx, &pb.SaveUserDetailRequest{
			Name:  user.Name,
			Age:   user.Age,
			Token: token,
		})
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{
			"success": res.Success,
		})
		return

	})
	r.PUT("/user/update", func(ctx *gin.Context) {
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization token is missing",
			})
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		var user User
		err := ctx.ShouldBind(&user)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		res, err := client.UpdateUserName(ctx, &pb.UpdateUserNameRequest{
			NewName: user.Name,
			Token:   token,
		})
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{
			"success": res.Success,
		})
		return

	})

	r.Run(":5000")

}
