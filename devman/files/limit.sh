#!/bin/sh
# tc htb rate limiting - upload (src ip) / download (dst ip)
CID=$2; IP=$3; RATE=${4:-0}; IF=br-lan
case "$1" in
  init) tc qdisc add dev $IF root handle 1: htb default 30 2>/dev/null ;;
  set)
    tc class change dev $IF parent 1: classid 1:$CID htb rate ${RATE}kbit ceil ${RATE}kbit 2>/dev/null
    tc filter replace dev $IF parent 1: prio 1 u32 match ip src $IP flowid 1:$CID 2>/dev/null
    ;;
  del)
    tc filter del dev $IF parent 1: prio 1 u32 match ip src $IP flowid 1:$CID 2>/dev/null
    tc class del dev $IF parent 1: classid 1:$CID 2>/dev/null
    ;;
  setdn)
    DNID="1${CID}"
    tc class change dev $IF parent 1: classid 1:$DNID htb rate ${RATE}kbit ceil ${RATE}kbit 2>/dev/null
    tc filter replace dev $IF parent 1: prio 1 u32 match ip dst $IP flowid 1:$DNID 2>/dev/null
    ;;
  deldn)
    DNID="1${CID}"
    tc filter del dev $IF parent 1: prio 1 u32 match ip dst $IP flowid 1:$DNID 2>/dev/null
    tc class del dev $IF parent 1: classid 1:$DNID 2>/dev/null
    ;;
  clean) tc qdisc del dev $IF root 2>/dev/null ;;
esac
