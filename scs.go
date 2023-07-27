package SCS

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

type Client struct {
	conn     net.Conn
	username string
}

type HistoryEntry struct {
	Ip       string
	Password string
	Username string
}

var (
	clients      = make(map[net.Conn]*Client)
	mutex        sync.Mutex
	ipserver     = "global"
	portserver   = "global"
	password     = "global"
	ip           = "global"
	port         = "global"
	history      []HistoryEntry
	maxPageSize  = 5
	historyFile  = ".history.txt"
	userSettings = ".settings.txt"
	userPassword = ""
	loginCount   = 0
)

func StartServer(ip, port, pass string) {
	ipserver = ip
	portserver = port
	password = pass

	address := ip + ":" + port
	listener, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer listener.Close()

	fmt.Println("Server listening on " + address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		go handleConnection(conn, pass)
	}
}

func handleConnection(conn net.Conn, pass string) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	password, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading password:", err)
		return
	}
	password = strings.TrimSpace(password)

	if password != pass {
		return
	}

	client := &Client{
		conn: conn,
	}

	// Add the client to the clients map
	mutex.Lock()
	clients[conn] = client
	mutex.Unlock()

	// Handle client messages
	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		message = strings.TrimSpace(message)

		if strings.HasPrefix(message, "?") {
			// Ignore the command if it starts with "?#"
			if strings.HasPrefix(message, "?#") {
				continue
			}

			// Handle other commands here
			if strings.HasPrefix(message, "?kick ") {
				username := strings.TrimSpace(strings.TrimPrefix(message, "?kick "))
				kickUser(username)
			}
			// Add more commands as needed
		}

		// Broadcast regular messages to clients
		formattedMessage := fmt.Sprintf("[%s]: %s", conn.RemoteAddr(), message)
		broadcastMessage(formattedMessage, conn)
	}

	// Remove the client from the clients map
	mutex.Lock()
	delete(clients, conn)
	mutex.Unlock()
}

func broadcastMessage(message string, sender net.Conn) {
	mutex.Lock()
	defer mutex.Unlock()

	for conn := range clients {
		if conn != sender {
			_, err := conn.Write([]byte(message + "\n"))
			if err != nil {
				fmt.Printf("Error broadcasting message: %s\n", err)
			}
		}
	}
}

func kickUser(username string) {
	mutex.Lock()
	defer mutex.Unlock()

	for conn, client := range clients {
		if client.username == username {
			conn.Close()
			delete(clients, conn)
			return
		}
	}
}

func StartClient(ip, port, pass string) {
	ipserver = ip
	portserver = port
	userPassword = pass

	loadHistory()
	loadUserSettings()
	defer saveHistory()

	conn, err := net.Dial("tcp", ip+":"+port)
	if err != nil {
		return
	}
	defer conn.Close()

	if loginCount == 0 {
		password := userPassword
		if password != userPassword {
			return
		}
		loginCount++
	}

	// Get username from history
	username := getUsernameFromHistory(ip)
	if username != "" {
		return
	}

	// Start listening for user input
	go listenForInput(conn)

	// Read and display messages from the server
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		message := scanner.Text()
		log.Println("[Server]:", message)
	}

	if scanner.Err() != nil {
		return
	}
}

func getUsernameFromHistory(ip string) string {
	for _, entry := range history {
		if entry.Ip == ip {
			return entry.Username
		}
	}
	return ""
}

func listenForInput(conn net.Conn) {
	scanner := bufio.NewScanner(os.Stdin)
	writer := bufio.NewWriter(conn)

	for scanner.Scan() {
		message := scanner.Text()

		_, err := writer.WriteString(message + "\n")
		if err != nil {
			break
		}
		err = writer.Flush()
		if err != nil {
			break
		}
	}

	if scanner.Err() != nil {
		log.Println("Error reading from input:", scanner.Err())
	}
}

func loadHistory() {
}

func saveHistory() {
}

func loadUserSettings() {
}

func saveUserSettings() {
}
