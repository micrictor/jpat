package cmd

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
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
	clientCmd.Flags().Duration("timeout", time.Second*5, "Client connection idle timeout")
	clientCmd.Flags().Duration("deadline", time.Minute*5, "Connection deadline (0 == unlimited)")
	clientCmd.Flags().String("jwtAlgo", "hs256", "JWT signature algorithm.")
	clientCmd.Flags().String("jwtSecret", "secretstring", "JWT signing secret. Behaviour depends on algo.")
	clientCmd.Flags().Duration("jwtDuration", time.Second*30, "Duration for the network access.")
}

func clientMain(cmd *cobra.Command, args []string) {
	server, _ := cmd.Flags().GetString("server")
	serverPort, _ := cmd.Flags().GetString("port")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	deadline, _ := cmd.Flags().GetDuration("deadline")
	tokenDialer := &net.Dialer{
		Timeout: timeout,
	}
	request, err := proto.Marshal(&pb.AuthRequest{
		Token: getOrCreateToken(cmd),
	})
	if err != nil {
		log.Fatalf("%v", err) // this should never happen
	}

	parentContext := context.Background()
	parentContext, cancelFunc := context.WithDeadline(parentContext, time.Now().Add(deadline))
	defer cancelFunc()

	log.Printf("attempting to connect to udp://%s:%s", server, serverPort)
	conn, err := tokenDialer.DialContext(parentContext, "udp", server+":"+serverPort)

	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	conn.Write(request)
	conn.Close()

	// create a listenconfig using parentConext
	listenConfig := net.ListenConfig{}
	localConn, err := listenConfig.ListenPacket(parentContext, conn.LocalAddr().Network(), conn.LocalAddr().String())
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	replyChannel := make(chan (pb.AuthReply))
	go clientListener(localConn, replyChannel)

	conn.Write(request)

	reply := <-replyChannel
	fmt.Printf("reply: %v\n", reply)
}

func clientListener(conn net.PacketConn, replyChannel chan (pb.AuthReply)) {
	buffer := make([]byte, 1024*8) // Max JWT size is 8KB
	n, _, err := conn.ReadFrom(buffer)
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

func getOrCreateToken(cmd *cobra.Command) string {
	inputToken, _ := cmd.Flags().GetString("token")
	if inputToken != "" {
		return inputToken
	}

	inputAlg, _ := cmd.Flags().GetString("jwtAlgo")
	inputAlg = strings.ToUpper(inputAlg)
	secret, _ := cmd.Flags().GetString("jwtSecret")
	duration, err := cmd.Flags().GetDuration("jwtDuration")
	if inputAlg == "" || secret == "" || err != nil {
		log.Fatalf("need to specify either token or JWT parameters")
		return ""
	}

	exp := time.Now().Add(duration).Unix()

	var claims jwt.MapClaims = make(map[string]interface{})
	claims["exp"] = exp

	alg := jwt.GetSigningMethod(inputAlg)
	if alg == nil {
		log.Fatalf("Couldn't find signing method: %v", inputAlg)
	}

	token := jwt.NewWithClaims(alg, claims)

	var key interface{}
	switch inputAlg {
	case "HS256":
		key = []byte(secret)
	case "RS256":
		fileHandle, err := os.Open(secret)
		if err != nil {
			log.Fatalf("Couldn't open rsa secret %v", err)
		}

		buf := new(bytes.Buffer)
		buf.ReadFrom(fileHandle)

		key, err = jwt.ParseRSAPrivateKeyFromPEM(buf.Bytes())
		if err != nil {
			log.Fatalf("Couldn't convert key data to key; Is it PEM-encoded? %v", err)
		}
	}

	out, err := token.SignedString(key)
	if err != nil {
		log.Fatalf("Couldn't sign jwt: %v", err)
	}

	return out
}
