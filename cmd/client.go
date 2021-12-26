package cmd

import (
	"fmt"
	"log"
	"net"

	"github.com/golang/protobuf/proto"
	pb "github.com/micrictor/jpat/pkg/jpat"
	"github.com/spf13/cobra"
)

// clientCmd represents the client command
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "JPAT Client Implementation",
	Long:  `Used to send a JWT into a JPAT server to request permission to connect via service port`,
	Run:   clientMain,
}

func init() {
	rootCmd.AddCommand(clientCmd)

	clientCmd.Flags().StringP("server", "s", "", "JPAT server to connect to")
	clientCmd.Flags().StringP("port", "p", "1337", "UDP port the JPAT server is listening on.")
	clientCmd.Flags().StringP("token", "t", "", "JWT token to pass")
}

func clientMain(cmd *cobra.Command, args []string) {
	server, _ := cmd.Flags().GetString("server")
	serverPort, _ := cmd.Flags().GetString("port")
	inputToken, _ := cmd.Flags().GetString("token")
	request, err := proto.Marshal(&pb.AuthRequest{
		Token: inputToken,
	})
	if err != nil {
		log.Fatalf("%v", err)
	}

	log.Printf("attempting to connect to udp://%s:%s", server, serverPort)
	conn, err := net.DialTimeout("udp", server+":"+serverPort, DIAL_TIMEOUT)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	conn.Write(request)
	conn.Close()

	localConn, err := net.ListenUDP(conn.LocalAddr().Network(), conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	replyChannel := make(chan (pb.AuthReply))
	go clientListener(localConn, replyChannel)

	conn.Write(request)

	reply := <-replyChannel
	fmt.Printf("reply: %v\n", reply)
}

func clientListener(localConn *net.UDPConn, replyChannel chan (pb.AuthReply)) {
	buffer := make([]byte, 1024*8) // Max JWT size is 8KB
	n, err := localConn.Read(buffer)
	if err != nil || n == 0 {
		log.Fatalf("read: %v", err)
	}

	var reply pb.AuthReply
	err = proto.Unmarshal(buffer[:n], &reply)
	if err != nil {
		log.Fatalf("unmarshal: %v", err)
	}

	replyChannel <- reply
}
