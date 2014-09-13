package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/akrennmair/gopcap"
	"os"
	"time"
)

var (
	server_ip  string
	input_file string
)

func init() {
	flag.StringVar(&server_ip, "server-ip", "114.66.198.5", "114.66.198.5")
	flag.StringVar(&input_file, "input", "target.cap", "pcap file")
}

type session_stat struct {
	id          int
	flags       uint16
	syn_tm      time.Time
	req_tm      time.Time
	rsp_tm      time.Time
	rfin_tm     time.Time
	sfin_tm     time.Time
	rcvd_length int
	sent_length int
	req_length  int
	rsp_length  int
	key         string
	sent_sn     uint32
	rcvd_sn     uint32
}

func duration_milli(end, begin time.Time) int64 {
	return int64(end.Sub(begin) / time.Millisecond)
}

const (
	ss_syn_rcvd uint16 = 1 << iota
	ss_syn_sent
	ss_push_rcvd
	ss_push_sent
	ss_fin_rcvd
	ss_fin_sent
)

func split_pcap(input, svrip string) error {
	sns := make(map[string]session_stat)

	f, err := os.Open(input)
	if err != nil {
		return err
	}
	defer f.Close()
	reader, err := pcap.NewReader(bufio.NewReader(f))
	if err != nil {
		return err
	}
	for pkt := reader.Next(); pkt != nil; pkt = reader.Next() {
		pkt.Decode()
		if pkt.IP == nil || pkt.TCP == nil {
			fmt.Println("unknown packet ", pkt.Time)
			continue
		}

		rcvd := pkt.IP.DestAddr() == svrip
		sent := pkt.IP.SrcAddr() == svrip
		if rcvd == false && sent == false {
			fmt.Println("discard", pkt.IP.DestAddr(), pkt.IP.SrcAddr())
			continue
		}
		daddr := pkt.IP.DestAddr() + "-" + u16_to_string(pkt.TCP.DestPort)
		saddr := pkt.IP.SrcAddr() + "-" + u16_to_string(pkt.TCP.SrcPort)
		key := daddr + "-" + saddr
		if sent {
			key = saddr + "-" + daddr
		}
		sess := sns[key]

		if rcvd == true && pkt.TCP.Flags&pcap.TCP_SYN != 0 && sess.flags&ss_syn_rcvd == 0 {
			sess.id++
			sess.flags = 0
			sess.syn_tm = pkt.Time
			sess.flags |= ss_syn_rcvd
			sess.rcvd_sn = pkt.TCP.Seq
			sess.sent_sn = 0
			sess.rcvd_length = 0
			sess.sent_length = 0
			sess.key = key
		}
		if sent == true && pkt.TCP.Flags&pcap.TCP_SYN != 0 && sess.flags&ss_syn_sent == 0 {
			sess.flags |= ss_syn_sent
			sess.sent_sn = pkt.TCP.Seq
		}
		payload := pkt.IP.Len() - int(pkt.IP.Ihl*4) - int(pkt.TCP.DataOffset*4)
		rseq := pkt.TCP.Seq - sess.rcvd_sn

		if sent {
			rseq = pkt.TCP.Seq - sess.sent_sn
		}
		if rcvd == true && pkt.TCP.Flags&pcap.TCP_PSH != 0 && (sess.flags&ss_push_rcvd) == 0 {
			sess.flags |= ss_push_rcvd
			sess.req_tm = pkt.Time
			sess.req_length = int(payload)
		}
		if sent == true && pkt.TCP.Flags&pcap.TCP_PSH != 0 && (sess.flags&ss_push_sent) == 0 {
			sess.flags |= ss_push_sent
			sess.rsp_tm = pkt.Time
			sess.rsp_length = int(payload)
		}
		if rcvd == true && pkt.TCP.Flags&pcap.TCP_FIN != 0 && sess.flags&ss_fin_rcvd == 0 {
			sess.flags |= ss_fin_rcvd
			sess.rfin_tm = pkt.Time
		}
		if sent == true && pkt.TCP.Flags&pcap.TCP_FIN != 0 && sess.flags&ss_fin_sent == 0 {
			sess.flags |= ss_fin_sent
			sess.sfin_tm = pkt.Time
		}

		if sent == true && sess.rcvd_length < int(rseq) {
			sess.rcvd_length = int(rseq)
		}
		if rcvd == true && sess.sent_length < int(rseq) {
			sess.sent_length = int(rseq)
		}

		if is_session_ok(sess) {
			fmt.Println(sess)
			sess.flags = 0
		}
		sns[key] = sess

	}
	return nil
}

func is_session_ok(this session_stat) bool {
	exp := ss_syn_rcvd | ss_syn_sent | ss_fin_rcvd | ss_fin_sent | ss_push_rcvd | ss_push_sent
	return this.flags&exp == exp
}

func (this session_stat) String() string {
	var (
		d  = duration_milli(this.sfin_tm, this.syn_tm)
		h  = duration_milli(this.rsp_tm, this.req_tm)
		hs = duration_milli(this.rfin_tm, this.req_tm)
	)
	return fmt.Sprint("du ", d, " handle ", h, " handle-sent ", hs, " rcvd-len ", this.rcvd_length, " sent-len ", this.sent_length, " req-len ", this.req_length, " resp-len ", this.rsp_length, " ", this.key, " id ", this.id)
}

func main() {
	flag.Parse()

	if !is_exist_file(input_file) {
		fmt.Errorf(input_file, "not exists")
		return
	}
	err := split_pcap(input_file, server_ip)
	fmt.Println(err)
}

func u16_to_string(v uint16) string {
	return fmt.Sprint(v)
}

func is_exist_file(fp string) bool {
	if _, err := os.Stat(fp); os.IsNotExist(err) {
		return false
	}
	return true
}
