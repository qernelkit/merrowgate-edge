package api

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"strconv"
)

// etagFor returns a strong ETag for a response body.
func etagFor(body []byte) string {
	sum := md5.Sum(body)
	return strconv.Quote(hex.EncodeToString(sum[:]))
}

// writeCacheable writes a JSON body with an ETag, or 304 when the client already
// holds this version. Depot dashboards poll these endpoints every few seconds.
func writeCacheable(w http.ResponseWriter, r *http.Request, body []byte) {
	tag := etagFor(body)
	w.Header().Set("ETag", tag)
	w.Header().Set("Cache-Control", "private, max-age=5")
	if r.Header.Get("If-None-Match") == tag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}
