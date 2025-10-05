package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

var (
	clients       = make(map[net.Conn]string)
	mutex         sync.Mutex
	port          = ":4562"
	encryptionKey = "fghjkmnbvc12345h"
)

func main() {

	args := os.Args
	if len(args) < 2 {
		log.Fatal("Not enough arguments")
	}

	var connectionType = args[1]
	var ipv4 = args[2]

	if ipv4 == "" || len(ipv4) == 0 {
		log.Fatal("Not enough arguments")
	}

	if connectionType == "-server" && ipv4 != "" {
		tcpServer()
	}
	if connectionType == "-client" && ipv4 != "" {
		tcpClient(ipv4)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	mutex.Lock()
	clients[conn] = conn.RemoteAddr().String()
	mutex.Unlock()

	buffer := make([]byte, 1024)
	for {

		n, err := conn.Read(buffer)
		if err != nil {
			log.Println(err)
			break
		}

		msg := string(buffer[:n])
		fmt.Printf("received from client %s: %s \n", conn.RemoteAddr().String(), msg)

		brodcast(conn, msg)
	}

	mutex.Lock()
	delete(clients, conn)
	mutex.Unlock()

	discMsg := fmt.Sprintf("client %s has disconnected \n", conn.RemoteAddr().String())
	fmt.Print(discMsg)
	brodcast(conn, discMsg)
}

func tcpServer() {

	listiner, err := net.Listen("tcp", port)
	if err != nil {
		log.Println(err)
	}

	defer listiner.Close()

	fmt.Printf("listening on port %s \n", port)
	for {
		conn, err := listiner.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn)
	}
}

func tcpClient(ipv4 string) {

	addr := ipv4 + port
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Println(err)
	}
	defer conn.Close()

	reader := bufio.NewReader(os.Stdin)

	go func() {
		buffer := make([]byte, 1024)
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				log.Println(err)
			}
			encryptedMessage := string(buffer[:n])
			decryptedMessage := decrypt(encryptedMessage, encryptionKey)

			fmt.Println(decryptedMessage)
		}
	}()

	for {
		text, _ := reader.ReadString('\n')
		msg := conn.RemoteAddr().String() + ": " + text

		if len(text) > 1 {
			encryptedMessage := encrypt(msg, encryptionKey)

			_, err = conn.Write([]byte(encryptedMessage))
			if err != nil {
				log.Println(err)
				break
			}
		}
	}

}

func brodcast(sender net.Conn, msg string) {
	mutex.Lock()
	defer mutex.Unlock()

	for conn := range clients {
		if conn != sender {
			conn.Write([]byte(msg))
		}
	}

}

func encrypt(message string, key string) string {
	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)

	}

	aesGCM, err := cipher.NewGCM(c)
	if err != nil {
		panic(err)

	}

	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		panic(err)
	}

	encrypted := aesGCM.Seal(nonce, nonce, []byte(message), nil)

	encoded := base64.StdEncoding.EncodeToString(encrypted)
	return encoded
}

func decrypt(message string, key string) string {
	aesByte, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		panic(err)
	}

	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)

	}

	aesGCM, err := cipher.NewGCM(c)
	if err != nil {
		panic(err)
	}
	nonceSize := aesGCM.NonceSize()

	nonce := aesByte[:nonceSize]
	ciphertext := aesByte[nonceSize:]

	decrypted, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}

	return string(decrypted)
}
