package main

import (
        "flag"
        "fmt"
        "net"
        "os"
        "os/exec"
        "time"
)

func main() {
        netconCommand := flag.NewFlagSet("netcon", flag.ExitOnError)
        netconIP := netconCommand.String("h", "", "IP address")
        netconPort := netconCommand.Int("p", 0, "Port")

        execCommand := flag.NewFlagSet("exec", flag.ExitOnError)
        execCmd := execCommand.String("c", "", "Shell command")

        chainCommand := flag.NewFlagSet("chain", flag.ExitOnError)
        chainIP := chainCommand.String("h", "", "IP address")
        chainPort := chainCommand.Int("p", 0, "Port")
        chainCmd := chainCommand.String("c", "", "Shell command")

        if len(os.Args) < 2 {
                fmt.Println("Usage:")
                fmt.Println("  netcon -h <IP> -p <Port>")
                fmt.Println("  exec -c <command>")
                fmt.Println("  chain -h <IP> -p <Port> -c <command>")
                os.Exit(1)
        }

        switch os.Args[1] {
        case "netcon":
                netconCommand.Parse(os.Args[2:])
                if *netconIP == "" || *netconPort == 0 {
                        fmt.Println("Missing IP address or port")
                        netconCommand.PrintDefaults()
                        os.Exit(1)
                }
                conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", *netconIP, *netconPort))
                if err != nil {
                        fmt.Println("Failed to connect:", err)
                        os.Exit(1)
                }
                conn.Close()

        case "exec":
                execCommand.Parse(os.Args[2:])
                if *execCmd == "" {
                        fmt.Println("Missing command")
                        execCommand.PrintDefaults()
                        os.Exit(1)
                }
                cmd := exec.Command("/bin/sh", "-c", *execCmd)
                cmd.Stdout = os.Stdout
                cmd.Stderr = os.Stderr
                err := cmd.Run()
                if err != nil {
                        fmt.Println("Failed to execute command:", err)
                        os.Exit(1)
                }

        case "chain":
                chainCommand.Parse(os.Args[2:])
                if *chainIP == "" || *chainPort == 0 || *chainCmd == "" {
                        fmt.Println("Missing IP address, port, or command")
                        chainCommand.PrintDefaults()
                        os.Exit(1)
                }
                conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", *chainIP, *chainPort))
                if err != nil {
                        fmt.Println("Failed to connect:", err)
                } else {
                        conn.Close()
                }

                time.Sleep(10 * time.Millisecond)

                cmd := exec.Command("/bin/sh", "-c", *chainCmd)
                cmd.Stdout = os.Stdout
                cmd.Stderr = os.Stderr
                err = cmd.Run()
                if err != nil {
                        fmt.Println("Failed to execute command:", err)
                        os.Exit(1)
                }

        default:
                fmt.Println("Invalid command")
                fmt.Println("Usage:")
                fmt.Println("  netcon -h <IP> -p <Port>")
                fmt.Println("  exec -c <command>")
                fmt.Println("  chain -h <IP> -p <Port> -c <command>")
                os.Exit(1)
        }
}