package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "jpat",
	Short: "JSON Packet Authorization Token usage",
	Long:  `JSON Packet Authorization Token client/server application`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
