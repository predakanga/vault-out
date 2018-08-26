// Copyright © 2018 Lachlan Pease <predatory.kangaroo@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	vaultUri string
	authRole string
	authSecret string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vault-out",
	Short: "Renders Vault secrets to file",
	Long: `Used to render your secrets from Hashicorp Vault to file.
Only changes files when necessary.

vault-out --server=https://vault secret/my-secret:foo /path/to/foo.dat secret/my-secret:bar /path/to/bar.dat`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: run,
	Args: validateArgs,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.vault-out.yaml)")
	rootCmd.PersistentFlags().StringVarP(&vaultUri, "server", "s", "", "Vault instance to use")
	rootCmd.PersistentFlags().StringVarP(&authRole, "auth-role", "r", "", "Vault AppRole role")
	rootCmd.PersistentFlags().StringVarP(&authSecret, "auth-secret", "p", "", "Vault AppRole secret")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".vault-out" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".vault-out")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func validateArgs(cmd *cobra.Command, args []string) error {
	if remainder := len(args) % 2; remainder != 0 {
		return errors.New("arguments must be given in pairs")
	}
	return nil
}

func splitSecret(secret string) (string, string) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		log.Fatalf("Invalid secret: %v (must be in the form path/to/secret:field)", secret)
	}
	return parts[0], parts[1]
}

func hashFileIfExists(filePath string) []byte {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return []byte{}
	}

	fp, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Couldn't open %v for reading: %v", filePath, err)
	}
	defer fp.Close()

	hasher := md5.New()
	if _, err := io.Copy(hasher, fp); err != nil {
		log.Fatalf("Failed to hash %v: %v", filePath, err)
	}
	return hasher.Sum(nil)
}

func run(cmd *cobra.Command, args []string) {
	vaultConf := api.DefaultConfig()
	if vaultConf.Error != nil {
		log.Fatalf("Vault config failed: %v", vaultConf.Error)
	}
	if vaultUri != "" {
		vaultConf.Address = vaultUri
	}
	vaultClient, err := api.NewClient(vaultConf)
	if err != nil {
		log.Fatalf("Couldn't connect to Vault: %v", err)
	}

	// TODO: Login
	authData := map[string]interface{} {
		"role_id": authRole,
		"secret_id": authSecret,
	}
	authSecret, err := vaultClient.Logical().Write("auth/approle/login", authData)
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}
	authToken := authSecret.Data["token"]
	if authToken == nil {
		log.Fatal("Authentication failed: No token returned")
	}
	vaultClient.SetToken(authToken.(string))

	changesMade := false
	for i := 0; i < len(args); i += 2 {
		secretPath, secretField := splitSecret(args[i])
		filePath := args[i+1]
		log.Printf("Rendering field %v of secret %v to file %v", secretField, secretPath, filePath)

		secret, err := vaultClient.Logical().Read(secretPath)
		if err != nil {
			log.Fatalf("Couldn't read secret %v: %v", secretPath, err)
		}
		newData := secret.Data[secretField]
		if newData == nil {
			log.Fatalf("Field %v does not exist in secret %v", secretField, secretPath)
		}
		newDataString, ok := newData.(string)
		if !ok {
			log.Fatalf("Field %v in secret %v must be a string (currently %T)", secretField, secretPath, newData)
		}
		newDataHash := md5.Sum([]byte(newDataString))
		oldDataHash := hashFileIfExists(filePath)

		if !bytes.Equal(newDataHash[:], oldDataHash) {
			fp, err := os.Create(filePath)
			if err != nil {
				log.Fatalf("Couldn't open %v for writing: %v", filePath, err)
			}
			defer fp.Close()
			if _, err := fp.WriteString(newDataString); err != nil {
				log.Fatalf("Couldn't write secret to %v: %v", filePath, err)
			}

			changesMade = true
		}
	}

	if changesMade {
		os.Exit(0)
	}
	os.Exit(1)
}
