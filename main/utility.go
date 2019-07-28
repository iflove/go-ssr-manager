package main

import (
	"crypto/md5"
	"fmt"
	"io"
	"math/rand"
	"strconv"
	"time"
)

func str(a ...interface{}) string {
	return fmt.Sprintf("%d", a)
}

func makeTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func makeMd5Token() string {
	nowTime := makeTimestamp()
	h := md5.New()
	_, e := io.WriteString(h, strconv.FormatInt(nowTime, 10))
	if e != nil {
		panic("makeMd5Token error.")
	}
	token := fmt.Sprintf("%x", h.Sum(nil))
	return token
}

func makeRangeNum(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	randNum := rand.Intn(max-min) + min
	return randNum
}

func formatAsDate() string {
	now := time.Now()
	year, month, day := now.Date()
	return fmt.Sprintf("%d/%02d/%02d - %02d:%02d:%02d", year, month, day, now.Hour(), now.Minute(), now.Second())
}
