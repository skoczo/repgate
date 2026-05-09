package cache

import (
	"strconv"
	"testing"

	"github.com/skoczo/repgate/internal/model"
)

func generateIpAddress(startingIP string, mask string, index int) string {
	// if index is greater than 255 remember to increment the third octet
	// take startingIP and split it into octets
	octets := make([]int, 4)
	for i, octet := range splitIP(startingIP) {
		octets[i] = octet
	}
	if index > 255 {
		octets[2] += index / 255
	}
	octets[3] += index % 255
	return strconv.Itoa(octets[0]) + "." + strconv.Itoa(octets[1]) + "." + strconv.Itoa(octets[2]) + "." + strconv.Itoa(octets[3])
}

func splitIP(ip string) []int {
	octets := make([]int, 4)
	for i, octet := range split(ip, ".") {
		octets[i], _ = strconv.Atoi(octet)
	}
	return octets
}

func split(s string, sep string) []string {
	var result []string
	current := ""
	for i := 0; i < len(s); i++ {
		if string(s[i]) == sep {
			result = append(result, current)
			current = ""
		} else {
			current += string(s[i])
		}
	}
	result = append(result, current)
	return result
}

func BenchmarkIPCacheSetExisting(b *testing.B) {
	cache := NewIPCache(1000)
	recordList := make([]model.IPRecord, 0, b.N)
	for i := 0; i < b.N; i++ {

		record := model.IPRecord{
			IP:    generateIpAddress("192.168.1.0", "255.255.0.0", i),
			Score: 80,
		}
		recordList = append(recordList, record)
	}
	for i := 0; i < b.N; i++ {
		cache.Set(recordList[i].IP, recordList[i])
	}
}

func BenchmarkIPCacheSetUnique(b *testing.B) {
	cache := NewIPCache(1000)
	for i := 0; i < b.N; i++ {
		ip := generateIpAddress("192.168.1.0", "255.255.0.0", i)
		record := model.IPRecord{
			IP:    ip,
			Score: 80,
		}
		cache.Set(record.IP, record)
	}
}

func BenchmarkIPCacheGet(b *testing.B) {
	cache := NewIPCache(1000)
	record := model.IPRecord{
		IP:    "192.168.1.1",
		Score: 80,
	}
	cache.Set(record.IP, record)
	for i := 0; i < b.N; i++ {
		cache.Get(record.IP)
	}
}

func BenchmarkIPCacheRemove(b *testing.B) {
	cache := NewIPCache(1000)
	record := model.IPRecord{
		IP:    "192.168.1.1",
		Score: 80,
	}
	cache.Set(record.IP, record)
	for i := 0; i < b.N; i++ {
		cache.Remove(record.IP)
	}
}
