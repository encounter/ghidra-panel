package ghidra

import (
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
)

var DefaultGrpcAddr = "127.0.0.1:13103"

func Connect(addr string) (GhidraClient, error) {
	log.Println("Using gRPC address", addr)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	c := NewGhidraClient(conn)
	return c, nil
}

var permDisplay = map[Permission]string{
	Permission_READ_ONLY: "Read",
	Permission_WRITE:     "Write",
	Permission_ADMIN:     "Admin",
	Permission_NONE:      "None",
}

func PermFromString(s string) Permission {
	v, ok := Permission_value[s]
	if ok {
		return Permission(v)
	}
	return -1
}

func PermDisplay(p Permission) string {
	return permDisplay[p]
}

var colorForPerm = map[Permission]int{
	Permission_READ_ONLY: 0x22bb33,
	Permission_WRITE:     0x5bc0de,
	Permission_ADMIN:     0xbb2124,
	Permission_NONE:      0x999999,
}

func PermColor(perm Permission) int {
	return colorForPerm[perm]
}

func PermColorHex(perm Permission) string {
	return fmt.Sprintf("#%06x", colorForPerm[perm])
}
