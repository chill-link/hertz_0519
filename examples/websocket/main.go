/*
 * Copyright 2022 CloudWeGo Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"context"
	"crypto/sha1"
	"encoding/base64"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/consts"
	"github.com/cloudwego/hertz/pkg/network"
)

func computeAcceptKey(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.Sum([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(h[:])
}

func echo(conn network.Conn) {
	defer conn.Close()
	header := make([]byte, 2)
	for {
		if _, err := conn.Read(header); err != nil {
			return
		}
		fin := header[0]&0x80 != 0
		opcode := header[0] & 0x0f
		masked := header[1]&0x80 != 0
		length := int(header[1] & 0x7f)
		if opcode == 0x8 { // close frame
			return
		}
		if !fin || !masked || opcode != 0x1 || length > 125 {
			return
		}
		maskKey := make([]byte, 4)
		if _, err := conn.Read(maskKey); err != nil {
			return
		}
		payload := make([]byte, length)
		if _, err := conn.Read(payload); err != nil {
			return
		}
		for i := 0; i < length; i++ {
			payload[i] ^= maskKey[i%4]
		}
		frame := append([]byte{0x81, byte(length)}, payload...)
		if _, err := conn.Write(frame); err != nil {
			return
		}
	}
}

func wsHandler(c context.Context, ctx *app.RequestContext) {
	if !ctx.IsGet() {
		ctx.String(consts.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	key := string(ctx.GetHeader("Sec-WebSocket-Key"))
	if key == "" {
		ctx.String(consts.StatusBadRequest, "Bad Request")
		return
	}

	ctx.Response.Header.SetStatusCode(consts.StatusSwitchingProtocols)
	ctx.Response.Header.Set("Upgrade", "websocket")
	ctx.Response.Header.Set("Connection", "Upgrade")
	ctx.Response.Header.Set("Sec-WebSocket-Accept", computeAcceptKey(key))
	ctx.Hijack(echo)
}

func main() {
	h := server.Default(server.WithHostPorts("127.0.0.1:8080"))
	h.GET("/ws", wsHandler)
	h.Spin()
}
