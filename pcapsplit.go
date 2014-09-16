package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	pcap "github.com/heartszhang/pcapsplit/gopcap"
)

var (
	server_ip  string
	input_file string
)

func init() {
	flag.StringVar(&server_ip, "server-ip", "123.125.20.36", "114.66.198.5")
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
	//	key         string
	sent_start   uint32
	rcvd_start   uint32
	sent_no      uint32
	rcvd_no      uint32
	sent_retrans int
	rcvd_retrans int
	pkt_rcvd     int
	pkt_sent     int
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

type statis struct {
	syn_count,
	psh_count,
	fin_count,
	pkt_count,
	cnn_count int
}

func (this statis) String() string {
	return fmt.Sprintf("syn %v psh %v fin %v pkt %v connection %v", this.syn_count, this.psh_count, this.fin_count, this.pkt_count, this.cnn_count)
}
func statis_session(sess session_stat, s *statis) {
	s.cnn_count++
	if sess.flags&ss_syn_rcvd != 0 {
		s.syn_count++
	}
	if sess.flags&(ss_fin_rcvd|ss_fin_sent) != 0 {
		s.fin_count++
	}
	if sess.flags&ss_push_rcvd != 0 {
		s.psh_count++
	}
}

func split_pcap(input, svrip string) error {
	var s statis
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

		if rcvd {
			sess.pkt_rcvd++
		} else {
			sess.pkt_sent++
		}
		s.pkt_count++
		if rcvd == true && pkt.TCP.Flags&pcap.TCP_SYN != 0 && sess.flags&ss_syn_rcvd == 0 {
			if sess.id != 0 {
				statis_session(sess, &s)
				diagnose_session(sess)
			}
			sess = session_stat{id: sess.id + 1}
			sess.syn_tm = pkt.Time
			sess.flags |= ss_syn_rcvd
			sess.rcvd_start = pkt.TCP.Seq
			//			sess.key = key
		}

		if sent == true && pkt.TCP.Flags&pcap.TCP_SYN != 0 && sess.flags&ss_syn_sent == 0 {
			sess.flags |= ss_syn_sent
			sess.sent_start = pkt.TCP.Seq
		}
		if sess.flags&(ss_fin_rcvd|ss_fin_sent) == ss_fin_rcvd|ss_fin_sent {
			continue
		}
		payload := pkt.IP.Len() - int(pkt.IP.Ihl*4) - int(pkt.TCP.DataOffset*4)
		rseq := pkt.TCP.Seq - sess.rcvd_start
		if rcvd && rseq > 0 {
			if rseq < sess.rcvd_no {
				sess.rcvd_retrans++
			} else {
				sess.rcvd_no = rseq
			}
		}
		if sent {
			rseq = pkt.TCP.Seq - sess.sent_start
			if rseq > 0 && rseq < sess.sent_no {
				sess.sent_retrans++
			} else if rseq > 0 {
				sess.sent_no = rseq
			}
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

		if sent == true && sess.sent_length < int(rseq) {
			sess.sent_length = int(rseq)
		}
		if rcvd == true && sess.rcvd_length < int(rseq) {
			sess.rcvd_length = int(rseq)
		}

		if is_session_ok(sess) {
			fmt.Println(sess)
		}
		sns[key] = sess

	}
	for _, v := range sns {
		statis_session(v, &s)
	}
	fmt.Println(s)
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
	return fmt.Sprint("du ", d, " handle ", h, " handle-sent ", hs, " rcvd-len ", this.rcvd_length, " sent-len ", this.sent_length, " req-len ", this.req_length, " resp-len ", this.rsp_length)
}

func diagnose_session(this session_stat) string {
	var flags []string
	if this.flags&ss_syn_rcvd != 0 {
		flags = append(flags, "syn-rcvd")
	}
	if this.flags&ss_syn_sent != 0 {
		flags = append(flags, "syn-sent")
	}
	if this.flags&ss_push_rcvd != 0 {
		flags = append(flags, "psh-rcvd")
	}
	if this.flags&ss_push_sent != 0 {
		flags = append(flags, "psh-sent")
	}
	return fmt.Sprint(strings.Join(flags, " "))
	/*	ss_syn_rcvd
		ss_syn_sent
		ss_push_rcvd
		ss_push_sent
		ss_fin_rcvd
		ss_fin_sent
	*/
}

func main() {
	flag.Parse()

	if !is_exist_file(input_file) {
		fmt.Errorf(input_file, "not exists")
		return
	}
	split_pcap(input_file, server_ip)
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
