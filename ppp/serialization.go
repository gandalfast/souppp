package ppp

type Serializer interface {
	Serialize() ([]byte, error)
}

type staticSerializer struct {
	d []byte
}

func (s staticSerializer) Serialize() ([]byte, error) {
	return s.d, nil
}

func NewStaticSerializer(data []byte) Serializer {
	return &staticSerializer{
		d: data,
	}
}

type Deserializer interface {
	Parse([]byte) error
}

type SerializerDeserializer interface {
	Serializer
	Deserializer
}
