// Copyright (c) 2019 Sunil Nimmagadda <sunil@nimmagadda.net>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"os"
	"strings"
)

const rspamdURL = "http://localhost:11333/checkv2"

var stdout *log.Logger

type session struct {
	ch      <-chan string
	control map[string]string
	id      string
	payload *strings.Builder
}

type rspamdResponse struct {
	Score         float32
	RequiredScore float32 `json:"required_score"`
	Subject       string
	Action        string
	DKIMSig       string `json:"dkim-signature"`
}

func linkConnect(s *session, args []string) {
	rdns, laddr := args[6], args[8]
	s.control["Pass"] = "all"
	p := strings.Split(laddr, ":")
	if p[0] != "local" {
		s.control["Ip"] = p[0]
	}
	if rdns != "" {
		s.control["Hostname"] = rdns
	}
}

func linkIdentify(s *session, args []string) {
	s.control["Helo"] = args[6]
}

func txBegin(s *session, args []string) {
	s.control["Queue-Id"] = args[6]
}

func txMail(s *session, args []string) {
	mailFrom, status := args[7], args[8]
	if status == "ok" {
		s.control["From"] = mailFrom
	}
}

func txRcpt(s *session, args []string) {
	rcptTo, status := args[7], args[8]
	if status == "ok" {
		s.control["Rcpt"] = rcptTo
	}
}

func txData(s *session, args []string) {
	status := args[7]
	if status == "ok" {
		s.control = nil
	}
}

func txCleanup(s *session, args []string) {
	s.control = nil
}

func filterCommit(s *session, args []string) {
	token := args[6]
	reason := <-s.ch
	if reason != "" {
		stdout.Printf("filter-result|%s|%s|reject|%s\n",
			token, s.id, reason)
		return
	}
	stdout.Printf("filter-result|%s|%s|proceed\n", token, s.id)
}

func filterDataLine(s *session, args []string) {
	token, line := args[6], args[7]
	if line != "." {
		s.payload.WriteString(line)
		s.payload.WriteString("\n")
		return
	}
	s.ch = dataOutput(s.control, token, s.id, s.payload.String())
}

func rspamdPost(hdrs map[string]string, data string) (*rspamdResponse, error) {
	r := strings.NewReader(data)
	client := &http.Client{}
	req, err := http.NewRequest("POST", rspamdURL, r)
	if err != nil {
		return nil, err
	}
	for k, v := range hdrs {
		req.Header.Add(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rr := &rspamdResponse{}
	if err := json.NewDecoder(resp.Body).Decode(rr); err != nil {
		return nil, err
	}
	return rr, nil
}

func dataOutput(headers map[string]string,
	token, id, data string) <-chan string {
	ch := make(chan string)
	go func() {
		resp, err := rspamdPost(headers, data)
		if err != nil {
			ch <- "421 Temporary failure"
			return
		}
		log.Printf("%v\n", resp)
		m, err := mail.ReadMessage(strings.NewReader(data))
		if err != nil {
			ch <- "421 Temporary failure"
			return
		}
		rejectReason := ""
		switch resp.Action {
		case "add header":
			m.Header["X-Spam"] = []string{"yes"}
			m.Header["X-Spam-Score"] = []string{
				fmt.Sprintf("%v / %v",
					resp.Score, resp.RequiredScore)}
		case "rewrite subject":
			m.Header["Subject"] = []string{resp.Subject}
		case "reject":
			rejectReason = "550 message rejected"
		case "greylist":
			rejectReason = "421 greylisted"
		case "soft reject":
			rejectReason = "451 try again later"
		}
		// Write DKIM-Signature header first if present
		if resp.DKIMSig != "" {
			stdout.Printf("filter-dataline|%s|%s|%s: %s\n",
				token, id, "DKIM-Signature", resp.DKIMSig)
		}
		// preserve order?
		for k, v := range m.Header {
			stdout.Printf("filter-dataline|%s|%s|%s: %s\n",
				token, id, k, strings.Join(v, ","))
		}
		// Blank line seperates headers and body
		stdout.Printf("filter-dataline|%s|%s|\n", token, id)
		s := bufio.NewScanner(m.Body)
		for s.Scan() {
			stdout.Printf("filter-dataline|%s|%s|%s\n",
				token, id, s.Text())
		}
		stdout.Printf("filter-dataline|%s|%s|%s\n", token, id, ".")
		ch <- rejectReason
	}()
	return ch
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("filter_rspamd: ")
	stdout = log.New(os.Stdout, "", 0)
	registry := map[string]struct {
		kind string
		fn   func(*session, []string)
	}{
		"link-connect":    {"report", linkConnect},
		"link-disconnect": {"report", nil},
		"link-identify":   {"report", linkIdentify},
		"tx-begin":        {"report", txBegin},
		"tx-data":         {"report", txData},
		"tx-mail":         {"report", txMail},
		"tx-rcpt":         {"report", txRcpt},
		"tx-commit":       {"report", txCleanup},
		"tx-rollback":     {"report", txCleanup},
		"commit":          {"filter", filterCommit},
		"data-line":       {"filter", filterDataLine},
	}
	for k, v := range registry {
		fmt.Printf("register|%s|smtp-in|%s\n", v.kind, k)
	}
	fmt.Println("register|ready")
	sessions := map[string]*session{}
	var event, id string
	stdin := bufio.NewScanner(os.Stdin)
	for stdin.Scan() {
		fields := strings.Split(stdin.Text(), "|")
		event, id = fields[4], fields[5]
		switch event {
		case "link-disconnect":
			delete(sessions, id)
		case "link-connect":
			sessions[id] = &session{
				control: map[string]string{},
				id:      id,
				payload: &strings.Builder{}}
			fallthrough
		default:
			if sessions[id] != nil {
				registry[event].fn(sessions[id], fields)
			}
		}
	}
}
