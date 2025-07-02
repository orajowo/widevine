package widevine

import (
	"crypto/cipher"
)

type Session struct {
	cdm   Cdm
	block cipher.Block
	keys  []Key
}

type Key struct {
	ID  []byte
	IV  []byte
	Key []byte
}

func Open(privateKey, clientID, pssh, licenseResponse []byte) (*Session, error) {
	var s Session
	if err := s.cdm.New(privateKey, clientID, pssh); err != nil {
		return nil, err
	}
	var res ResponseBody
	if err := res.Unmarshal(licenseResponse); err != nil {
		s.Close()
		return nil, err
	}
	block, err := s.cdm.Block(res)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.block = block

	// Decrypt and store all keys
	for k := range res.Container() {
		id := k.Id()
		if len(id) == 0 {
			// skip key container no ID
			continue
		}
		s.keys = append(s.keys, Key{
			ID:  id,
			IV:  k.iv(),
			Key: k.Key(block),
		})
	}
	return &s, nil
}

func (s *Session) RequestBody() ([]byte, error) {
	return s.cdm.RequestBody()
}

func (s *Session) Keys() []Key {
	return s.keys
}

func (s *Session) Close() {
	s.cdm = Cdm{}
	s.block = nil
	s.keys = nil
}
