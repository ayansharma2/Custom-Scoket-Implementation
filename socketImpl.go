package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"
)

var connectionFound = false
var handShake HandShake
var messages []string
var stopFinding = false
var otherPublicKey string
var authKey string
var urlCalled string

func initSocket(port string) {
	runtime.GOMAXPROCS(2)
	var wg sync.WaitGroup
	wg.Add(1)
	go startListening(port)
	startFinding(port)
	wg.Wait()
}

func startFinding(port string) {
	portDetails := HandShake{Port: port}
	b, _ := json.Marshal(&portDetails)
	var i int64

	for !connectionFound {
		for i = 0; i < 65535 && !connectionFound; i++ {
			if strconv.FormatInt(i, 10) == port {
				continue
			}
			if connectionFound {
				break
			}
			client := http.Client{
				Timeout: 10 * time.Millisecond,
			}
			urlCalled := "http://127.0.0.1:" + strconv.FormatInt(i, 10)
			req, err := http.NewRequest("POST", urlCalled, bytes.NewBuffer(b))
			req.Close = true
			res, err := client.Do(req)
			if err == nil {

				b, _ := io.ReadAll(res.Body)

				err := json.Unmarshal(b, &handShake)
				if err != nil {
					continue
				}

				if handShake.Port != "" {
					connectionFound = true
					messages = append(messages, "Connection Established with "+urlCalled)
					reRender()
					go startSending()
				}
				err = res.Body.Close()
				if err != nil {
					fmt.Println("Error Closing Request Body")
					return
				}
			}
		}
	}

}

func reRender() {
	clearScreen()
	for _, message := range messages {
		fmt.Println(message)
	}
	fmt.Print("Enter Message to Send : ")
}

func clearScreen() {
	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error Clearing Screen")
		return
	}
}

func startListening(port string) {
	http.HandleFunc("/getToken", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Got Request fot sending Auth Token")
		defer func() {
			connectionFound = true
		}()
		token := getEncryptedKey(urlCalled, otherPublicKey)
		fmt.Fprintf(w, token)
		startSending()
		fmt.Printf("Connection Established")
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if connectionFound {
			decoder := json.NewDecoder(r.Body)
			var message Message
			err := decoder.Decode(&message)
			if err != nil {
				fmt.Println("Error Decoding Received Message")
				return
			}
			finalLine := "Received Message : " + message.Data
			messages = append(messages, finalLine)
			reRender()

		} else {
			b, _ := io.ReadAll(r.Body)
			err := json.Unmarshal(b, &handShake)
			fmt.Println()
			if err != nil {
				fmt.Println("Error Unmarshalling received Handshake Object")
				return
			}
			if handShake.Port != "" {
				myPortDetails := HandShake{Port: port}
				b, err := json.Marshal(myPortDetails)
				if err != nil {
					fmt.Println("Error Converting struct to bye during returning response")
				}
				printDebugMessage("Response Sent " + string(b))
				_, err = fmt.Fprint(w, string(b))
				if err != nil {
					return
				}
				//localPublicKey, _ := ExportRsaPublicKeyAsPemStr(&keypair.PublicKey)
				//myHandShake := &HandShake{Port: port, AuthKey: getEncryptedKey(r.RemoteAddr, handShake.PublicKey), PublicKey: localPublicKey}
				//b, _ := json.Marshal(myHandShake)
				//w.Header().Set("Content-Type", "application/json")
				//fmt.Fprintf(w, string(b))
				//r.Body.Close()
				//time.Sleep(1 * time.Second)
				//url := "http://127.0.0.1:" + handShake.Port + "/getToken"
				//fmt.Println(url)
				//res, _ := http.Get(url)
				//var authKeyByteArray []byte
				//res.Body.Read(authKeyByteArray)
				//fmt.Println(string(authKeyByteArray))
				//authKey = string(authKeyByteArray)
				if !connectionFound {
					connectionFound = true
					messages = append(messages, "Connection Established with http://127.0.0.1:"+handShake.Port)
					reRender()
					go startSending()
				}
			}

		}

	})
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		fmt.Println("Error Starting Server")
		return
	}
}

func printDebugMessage(message string) {
	//fmt.Println(message)
}

func startSending() {
	for {
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		postBody, _ := json.Marshal(map[string]string{
			"data": line,
		})
		body := bytes.NewBuffer(postBody)
		client := http.Client{
			Timeout: 2 * time.Second,
		}
		_, err = client.Post("http://127.0.0.1:"+handShake.Port, "application/json", body)
		if err != nil {
			fmt.Println(err)
		} else {
			finalMessage := "Sent Message : " + line
			messages = append(messages, finalMessage)
			reRender()
		}
	}
}

type HandShake struct {
	Port      string `json:"port"`
	PublicKey string `json:"publicKey"`
	AuthKey   string `json:"authKey"`
}

type Message struct {
	Data string `json:"data"`
}
