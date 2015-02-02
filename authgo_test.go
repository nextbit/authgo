package authgo

import "testing"

func TestCreatePassword(t *testing.T) {
	p := CreatePassword("123456")

	if p.Hash == "" {
		t.Error("Expected not null, got", p.Hash)
	}

	if p.Salt == "" {
		t.Error("Expected not null, got", p.Salt)
	}
}

func TestCreatePasswordIsDifferent(t *testing.T) {
	p1 := CreatePassword("123456")
	p2 := CreatePassword("654321")

	if p1.Hash == p2.Hash {
		t.Error("p1 and p2 hash should be different, but was the same")
	}

	if p1.Salt == p2.Salt {
		t.Error("p1 and p2 hash should be different, but was the same")
	}
}

func TestPasswordMatchRightPass(t *testing.T) {
	p := CreatePassword("123456")

	pm := PasswordMatch("123456", &p)
	if pm != true {
		t.Error("Expected true, got", pm)
	}
}

func TestPasswordMatchWrongPass(t *testing.T) {
	p := CreatePassword("123456")

	pm := PasswordMatch("654321", &p)
	if pm != false {
		t.Error("Expected false, got", pm)
	}
}
