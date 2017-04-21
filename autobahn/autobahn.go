/*
 * server for autobahn test
 *
 * in one terminal, run:
 *   ./autobahn
 * in another terminal, run:
 *   ./autobahn.sh
 * open reports/servers/index.html to see test results
 */

package main

import (
    "net/http"
    "io"
    "websock"
)

func handler(w http.ResponseWriter, r *http.Request) {
    upgrader := websock.Upgrader { 1024, 1024 }
    conn, _ := upgrader.Upgrade(w, r)

    buf := make([]byte, 1024)
    for {
        messageType, reader, err := conn.NextReader()
        if err != nil {
            if err == io.EOF {
                continue
            } else if err == websock.CONNECTION_CLOSED {
                return
            }
            panic(err)
        }

        input := []byte {}
        for {
            n, err := reader.Read(buf)
            if err != nil {
                if err == io.EOF {
                    break
                }
                panic(err)
            }
            input = append(input, buf[:n]...)
        }
        writer, _ := conn.NextWriter(messageType)
        writer.Write(input)
    }
}

func main() {
    http.HandleFunc("/", handler)
    http.ListenAndServe("localhost:8200", nil)
}
