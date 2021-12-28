package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/spf13/cobra"

	"github.com/micrictor/jpat/internal/config"
	"github.com/micrictor/jpat/internal/rules"
	"github.com/micrictor/jpat/internal/token"
	pb "github.com/micrictor/jpat/pkg/jpat"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the jpat server",
	Long:  `JPAT Single-Packet Authorization server`,
	Run: func(cmd *cobra.Command, args []string) {
		serverMain(cmd)
	},
}

const DIAL_TIMEOUT = 5 * 1000000000 // 5 second timeout

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.PersistentFlags().IPP("listenAddr", "a", net.IPv4zero, "The address to listen on.")
	serverCmd.PersistentFlags().IntP("listenPort", "p", 1337, "The UDP port to listen on.")
	serverCmd.PersistentFlags().StringP("configFile", "c", "./jpat.yml", "The JPAT config file")
}

func serverMain(cmd *cobra.Command) {
	log.SetPrefix("[JpatServer] ")

	listenAddr, _ := cmd.PersistentFlags().GetIP("listenAddr")
	listenPort, _ := cmd.PersistentFlags().GetInt("listenPort")
	configFile, _ := cmd.PersistentFlags().GetString("configFile")
	file, err := os.Open(configFile)
	if err != nil {
		log.Fatalf("Failed to open config file %s: %v", configFile, err)
	}
	appConfig := config.New(file)
	log.Printf("Using config %v", appConfig)

	s, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", listenAddr, listenPort))
	if err != nil {
		fmt.Println(err)
		return
	}

	conn, err := net.ListenUDP("udp", s)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Listening on %s", conn.LocalAddr().String())

	defer conn.Close()

	for {
		buffer := make([]byte, 1024*8) // Max JWT size is 8KB
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Println(err)
		}
		log.Printf("Recieved request from %s", addr.String())

		go processPacket(addr, buffer[:n], appConfig)
	}
}

func processPacket(addr *net.UDPAddr, buffer []byte, appConfig *config.AppConfig) {
	var authRequest pb.AuthRequest
	err := proto.Unmarshal(buffer, &authRequest)
	if err != nil {
		log.Printf("Error unmarshaling input: %s", err.Error())
		return
	}

	inputToken, err := token.ProcessToken(authRequest.Token, appConfig)
	if err != nil {
		log.Printf("token processing failed: %v", err)
		return
	}
	matchedRule, err := rules.GetRule(addr, inputToken, appConfig)
	if err != nil {
		log.Printf("rule matching failed: %v", err)
		return
	}

	// Send the reply back before applying firewall policies
	var sb strings.Builder
	sb.WriteString(appConfig.Service.Host)
	sb.WriteRune(':')
	sb.WriteString(fmt.Sprintf("%d", appConfig.Service.Port))
	reply := pb.AuthReply{
		Socket:     sb.String(),
		Expiration: int64(matchedRule.Expiration),
	}
	replyChan := make(chan (error))
	go sendReply(reply, addr, replyChan)

	if err := rules.ApplyRule(matchedRule); err != nil {
		log.Printf("Error applying rule: %v", err)
		return
	}

	replyErr := <-replyChan
	if replyErr != nil {
		log.Printf("Error sending reply: %s", replyErr.Error())
		return
	}
}

func sendReply(reply pb.AuthReply, addr *net.UDPAddr, doneChan chan (error)) {
	conn, err := net.DialTimeout("udp", addr.String(), DIAL_TIMEOUT)
	if err != nil {
		doneChan <- err
	}

	serializedReply, err := proto.Marshal(&reply)
	if err != nil {
		doneChan <- err
	}
	n, err := conn.Write(serializedReply)
	log.Printf("%d bytes written", n)
	conn.Close()
	doneChan <- err
	log.Printf("Replied to %s with %s", addr.String(), reply.String())
}
