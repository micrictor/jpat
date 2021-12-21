package cmd

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/spf13/cobra"
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

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.PersistentFlags().IPP("listenAddr", "a", net.IPv4zero, "The address to listen on.")
	serverCmd.PersistentFlags().IntP("listenPort", "p", 1337, "The UDP port to listen on.")
	serverCmd.PersistentFlags().String("ipStack", "ipv4", "ipv4 or ipv6")

}

func serverMain(cmd *cobra.Command) {
	log.SetPrefix("[JpatServer] ")

	listenAddr, _ := cmd.PersistentFlags().GetIP("listenAddr")
	listenPort, _ := cmd.PersistentFlags().GetInt("listenPort")
	ipStack, _ := cmd.PersistentFlags().GetString("ipStack")

	var udpNetwork string

	if strings.ToLower(ipStack) == "ipv4" {
		udpNetwork = "udp4"
	}
	if strings.ToLower(ipStack) == "ipv6" {
		udpNetwork = "udp6"
	}
	if udpNetwork == "" {
		log.Fatalf("Unsupported IP Stack %s", ipStack)
	}

	s, err := net.ResolveUDPAddr(udpNetwork, fmt.Sprintf("%s:%d", listenAddr, listenPort))
	if err != nil {
		fmt.Println(err)
		return
	}

	conn, err := net.ListenUDP(udpNetwork, s)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Listening on %s", conn.LocalAddr().String())

	defer conn.Close()

	for {
		buffer := make([]byte, 1024*8) // Max JWT size is 8KB
		_, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Println(err)
		}
		log.Printf("Recieved request from %s", addr.String())

		processPacket(udpNetwork, addr, buffer)
	}
}

func processPacket(udpNet string, addr *net.UDPAddr, buffer []byte) {
	// Send the reply back before applying firewall policies
	replyChan := make(chan (error))
	sendReply(udpNet, addr, replyChan)

	replyErr := <-replyChan
	if replyErr != nil {
		log.Printf("Error sending reply: %s", replyErr.Error())
	}
}

func sendReply(udpNet string, addr *net.UDPAddr, doneChan chan (error)) {
	log.Printf("Replying to %s with service socket %s", addr.String(), addr.String())
	conn, err := net.DialUDP("udp6", nil, addr)
	if err != nil {
		doneChan <- err
	}

	_, err = conn.WriteToUDP([]byte(addr.String()), addr)
	doneChan <- err
}
