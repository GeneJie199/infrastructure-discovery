package docker

import "testing"

func TestParse(t *testing.T) {
	data := []byte(`{"ID":"abc","Names":"api","Image":"example/api:1","Command":"java --token secret","State":"running","Status":"Up 2 hours","Ports":"0.0.0.0:8080->8080/tcp","Labels":"com.docker.compose.project=shop"}` + "\n")
	got, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "api" || got[0].Image != "example/api:1" {
		t.Fatalf("containers = %+v", got)
	}
}
