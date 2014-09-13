package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/akrennmair/gopcap"
)

var (
	dest_ip    string
	target_dir string
	input_file string
)

func init() {

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
	req_length  uint32
	rsp_length  uint32
	key         string
}

const (
	ss_reserved = 1 << iota
	ss_syn_rcvd
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
		if rcvd == false || sent == false {
			fmt.Println("discard", pkt.IP.DestAddr(), pkt.IP.SrcAddr())
			continue
		}
		daddr := pkt.IP.DestAddr() + "-" + u16_to_string(pkt.TCP.DestPort)
		saddr := pkt.IP.SrcAddr() + "-" + u16_to_string(pkt.TCP.SrcPort)
		key := daddr + "_" + saddr
		if sent {
			key = saddr + "_" + daddr
		}
		sess := sns[key]
		if rcvd == true && pkt.TCP.Flags&pcap.TCP_SYN != 0 && sess.flags&ss_syn_rcvd == 0 {
			sess.id++
			sess.flags = 0
			sess.syn_tm = pkt.Time
			sess.flags |= ss_syn_rcvd
		}
		if sent == true && pkt.TCP.Flags&pcap.TCP_SYN != 0 && sess.flags&ss_syn_sent == 0 {
			sess.flags |= ss_syn_sent
		}
		if rcvd == true && pkt.TCP.Flags&pcap.TCP_PSH != 0 && (sess.flags&ss_push_rcvd) == 0 {
			sess.flags |= ss_push_rcvd
			sess.req_tm = pkt.Time
			sess.req_length = pkt.Len - uint32(pkt.TCP.DataOffset)
		}
		if sent == true && pkt.TCP.Flags&pcap.TCP_PSH != 0 && (sess.flags&ss_push_sent) == 0 {
			sess.flags |= ss_push_sent
			sess.rsp_tm = pkt.Time
			sess.rsp_length = pkt.Len - uint32(pkt.TCP.DataOffset)
		}
		if rcvd == true && pkt.TCP.Flags&pcap.TCP_FIN != 0 && sess.flags&ss_fin_rcvd == 0 {
			sess.flags |= ss_fin_rcvd
			sess.rfin_tm = pkt.Time
		}
		if sent == true && pkt.TCP.Flags&pcap.TCP_FIN != 0 && sess.flags&ss_fin_sent == 0 {
			sess.flags |= ss_fin_sent
			sess.sfin_tm = pkt.Time
		}
		payload := pkt.IP.Len() - int(pkt.IP.Ihl*4) - int(pkt.TCP.DataOffset*4)

		if sent == true && int(sess.rcvd_length) < pkt.TCP.Ack {
			sess.rcvd_length = pkt.TCP.Ack
		}
		if rcvd == true && int(sess.sent_length) < pkt.TCP.Ack {
			sess.sent_length = pkt.TCP.Ack
		}
		/*
					if rcvd == true && sess.rcvd_length < int(pkt.TCP.Seq)+payload {
						sess.rcvd_length = pkt.TCP.Seq + payload
					}
			    			if sent == true && sess.sent_length < pkt.TCP.Seq+payload {
							sess.sent_length = pkt.TCP.Seq + payload
						}
		*/
		if is_session_ok(sess) == true {
			fmt.Println(sess)
		}
	}
	return nil
}

func is_session_ok(this session_stat) bool {
	exp := ss_syn_rcvd | ss_syn_sent | ss_fin_rcvd | ss_fin_sent | ss_push_rcvd | ss_push_sent
	return this.flags&exp == exp
}

func (this session_stat) String() string {
	var (
		d  = int64(this.sfin_tm.Sub(this.syn_tm) / time.Millisecond)
		h  = int64(this.rsp_tm.Sub(this.req_tm) / time.Millisecond)
		hs = int64(this.rfin_tm.Sub(this.rsp_tm) / time.Millisecond)
	)
	return fmt.Sprintf(this.key, "id", this.id, "duration", d, "handle", h, "handle-sent", hs, "rcvd-len", this.rcvd_length, "sent-len", this.sent_length)
}

func main() {
	flag.Parse()
	if err := exist_file(input_file); err != nil {
		panic(err)
	}
	if err := exist_directory(target_dir); err != nil {
		panic(err)
	}
	err := split_pcap(input_file, target_dir)
	fmt.Println(err)
}

func u16_to_string(v uint16) string {
	return fmt.Sprint(v)
}
func is_exist_file(fp string) bool {
	return false
}
func is_exist_directory(dir string) bool {
	return false
}
