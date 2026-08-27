package admin_test

import (
	"io"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/stormlimitless/vakt/internal/auth"
)

func TestUserCrudAndTotpEnrol(t *testing.T) {
	a, srv, client := loginAdmin(t)
	csrf := csrfFrom(t, get(t, client, srv.URL+"/admin/users/new"))
	if resp := post(t, client, srv.URL+"/admin/users/new", url.Values{"csrf": {csrf}, "username": {"bob"}, "password": {"password1"}, "role": {"member"}}); resp.StatusCode != 303 {
		t.Fatalf("create %d", resp.StatusCode)
	}
	u, _ := a.Store.UserByName("bob")
	id := strconv.FormatInt(u.ID, 10)
	post(t, client, srv.URL+"/admin/users/"+id+"/totp/start", url.Values{"csrf": {csrf}})
	u, _ = a.Store.UserByName("bob")
	secret, pending := auth.TOTPPending(a.Cipher, u.TOTPSecretEnc)
	if !pending {
		t.Fatal("secret not pending after start")
	}
	if resp := get(t, client, srv.URL+"/admin/users/"+id+"/totp"); resp.StatusCode != 200 {
		t.Fatal("qr page")
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if resp := post(t, client, srv.URL+"/admin/users/"+id+"/totp/confirm", url.Values{"csrf": {csrf}, "code": {code}}); resp.StatusCode != 303 || strings.Contains(resp.Header.Get("Location"), "error") {
		t.Fatalf("confirm %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	u, _ = a.Store.UserByName("bob")
	if _, ok := auth.TOTPEnrolled(a.Cipher, u.TOTPSecretEnc); !ok {
		t.Fatal("not enrolled after confirm")
	}
	post(t, client, srv.URL+"/admin/users/"+id+"/totp/reset", url.Values{"csrf": {csrf}})
	u, _ = a.Store.UserByName("bob")
	if len(u.TOTPSecretEnc) != 0 {
		t.Fatal("reset did not clear")
	}
	post(t, client, srv.URL+"/admin/users/"+id+"/delete", url.Values{"csrf": {csrf}, "confirm": {"on"}})
	if _, err := a.Store.UserByName("bob"); err == nil {
		t.Fatal("not deleted")
	}
}

func TestCannotDeleteLastAdmin(t *testing.T) {
	a, srv, client := loginAdmin(t)
	csrf := csrfFrom(t, get(t, client, srv.URL+"/admin/users"))
	u, _ := a.Store.UserByName("henri")
	if resp := post(t, client, srv.URL+"/admin/users/"+strconv.FormatInt(u.ID, 10)+"/delete", url.Values{"csrf": {csrf}, "confirm": {"on"}}); resp.StatusCode != 400 {
		t.Fatalf("%d", resp.StatusCode)
	}
}

func TestStatusPage(t *testing.T) {
	_, srv, client := loginAdmin(t)
	resp := get(t, client, srv.URL+"/admin/status")
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "test") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
}
