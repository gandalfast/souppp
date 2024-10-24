package pppoe

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Tag is the interface for PPPoE Tag
type Tag interface {
	// Serialize Tag into byte slice
	Serialize() ([]byte, error)
	// Parse buf into Tag
	Parse(buf []byte) (int, error)
	// Type return PPPoE Tag type as uint16
	Type() uint16
	// String returns a string representation of Tag
	String() string
}

// TagEndOfList is the End-of-List tag
type TagEndOfList struct{}

func (eol TagEndOfList) Serialize() ([]byte, error) {
	var r [4]byte
	return r[:], nil
}

func (eol TagEndOfList) Parse(buf []byte) (int, error) {
	if binary.BigEndian.Uint16(buf[:2]) != 0 {
		return 0, fmt.Errorf("failed to parse %v, type is not %d", TagTypeEndOfList.String(), TagTypeEndOfList)
	}
	if binary.BigEndian.Uint16(buf[2:4]) != 0 {
		return 0, fmt.Errorf("failed to parse %v, length is not zero", TagTypeEndOfList.String())
	}
	return 4, nil
}

func (eol TagEndOfList) Type() uint16 {
	return uint16(TagTypeEndOfList)
}

func (eol TagEndOfList) String() string {
	return TagTypeEndOfList.String()
}

// TagByteSlice is for all byte slice and unknown type of tag, e.g. ACuniq, ACCookie
type TagByteSlice struct {
	TagType TagType
	Value   []byte
}

func (bslice *TagByteSlice) Serialize() ([]byte, error) {
	header := make([]byte, 4)
	binary.BigEndian.PutUint16(header[0:2], uint16(bslice.TagType))
	binary.BigEndian.PutUint16(header[2:4], uint16(len(bslice.Value)))
	return append(header, bslice.Value...), nil
}

func (bslice *TagByteSlice) Parse(buf []byte) (int, error) {
	bslice.TagType = TagType(binary.BigEndian.Uint16(buf[:2]))
	bslice.Value = buf[4 : binary.BigEndian.Uint16(buf[2:4])+4]
	return 4 + len(bslice.Value), nil
}

func (bslice *TagByteSlice) Type() uint16 {
	return uint16(bslice.TagType)
}

func (bslice *TagByteSlice) String() string {
	return fmt.Sprintf("%v: %X", bslice.TagType, bslice.Value)
}

// TagString is for all string type of tag, like ACName,SVCName
type TagString struct {
	*TagByteSlice
}

func (str *TagString) String() string {
	if len(str.TagByteSlice.Value) == 0 && str.TagType == TagTypeServiceName {
		return fmt.Sprintf("%v: %v", TagTypeServiceName, "<any service>")
	}
	return fmt.Sprintf("%v: %v", str.TagType, string(str.Value))
}

// BBFTag represents a vendor-specific PPPoE tag, which could include multiple sub-tag
type BBFTag struct {
	tags []Tag
}

func (bbf *BBFTag) Parse(buf []byte) (int, error) {
	if len(buf) < 8 {
		return 0, fmt.Errorf("not enought bytes for a BBF tag")
	}
	if binary.BigEndian.Uint16(buf[:2]) != 0x105 || binary.BigEndian.Uint32(buf[4:8]) != 0xde9 {
		return 0, fmt.Errorf("invalid BBF tag")
	}
	tagLen := binary.BigEndian.Uint16(buf[2:4])
	if tagLen < 4 {
		return 0, fmt.Errorf("invalid BBF tag length")
	}

	offset := 8
	for i := 0; i < _maxTags; i++ {
		subTag := createBBFSubTag(BBFSubTagNum(buf[offset]))
		n, err := subTag.Parse(buf[offset:])
		if err != nil {
			return 0, fmt.Errorf("failed to parse BBF subtag,%w", err)
		}
		offset += n
		bbf.tags = append(bbf.tags, subTag)
		if offset >= len(buf) {
			// Finished tag parsing
			break
		}

		// Reached maximum tags but there are others to parse
		if i == _maxTags-1 {
			return 0, fmt.Errorf("invalid BBF tag, exceed max number of subtags: %d", _maxTags)
		}
	}
	return int(tagLen) + 4, nil
}

func (bbf *BBFTag) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint16(buf[:2], 0x105)
	binary.BigEndian.PutUint32(buf[4:8], 0xde9)
	tagLen := 4
	for _, t := range bbf.tags {
		newt, err := t.Serialize()
		if err != nil {
			return nil, err
		}
		tagLen += len(newt)
		buf = append(buf, newt...)
	}
	binary.BigEndian.PutUint16(buf[2:4], uint16(tagLen))
	return buf, nil
}

func (bbf *BBFTag) Type() uint16 {
	return uint16(TagTypeVendorSpecific)
}

func (bbf *BBFTag) String() string {
	var b strings.Builder
	b.WriteString("VendorSpecific, BBF: ")
	for _, t := range bbf.tags {
		b.WriteByte('[')
		b.WriteString(t.String())
		b.WriteByte(']')
	}
	return b.String()
}

// BBFSubTagUint32 is for all numeric type of BBF sub-tag
type BBFSubTagUint32 struct {
	TagType BBFSubTagNum
	Value   uint32
}

func (num *BBFSubTagUint32) Serialize() ([]byte, error) {
	buf := make([]byte, 6)
	buf[0] = byte(num.TagType)
	buf[1] = 4
	return buf, nil
}

func (num *BBFSubTagUint32) Parse(buf []byte) (int, error) {
	num.TagType = BBFSubTagNum(buf[0])
	num.Value = binary.BigEndian.Uint32(buf[2:6])
	return 6, nil
}

func (num *BBFSubTagUint32) Type() uint16 {
	return uint16(num.TagType)
}

func (num *BBFSubTagUint32) String() string {
	return fmt.Sprintf("%v: %v", num.TagType, num.Value)
}

// BBFSubTagByteSlice is for all byte slice type BBF sub-tag
type BBFSubTagByteSlice struct {
	TagType BBFSubTagNum
	Value   []byte
}

func (bslice *BBFSubTagByteSlice) Serialize() ([]byte, error) {
	if len(bslice.Value) > 255 {
		return nil, fmt.Errorf("slice is too long")
	}
	header := make([]byte, 2)
	header[0] = byte(bslice.TagType)
	header[1] = byte(len(bslice.Value))
	return append(header, bslice.Value...), nil
}

func (bslice *BBFSubTagByteSlice) Parse(buf []byte) (int, error) {
	bslice.TagType = BBFSubTagNum(buf[0])
	bslice.Value = buf[2 : buf[1]+2]
	return 2 + len(bslice.Value), nil
}

func (bslice *BBFSubTagByteSlice) Type() uint16 {
	return uint16(bslice.TagType)
}

func (bslice *BBFSubTagByteSlice) String() string {
	return fmt.Sprintf("%v: %X", bslice.TagType, bslice.Value)
}

// BBFSubTagString is for string type of BBF sub-tag
type BBFSubTagString struct {
	*BBFSubTagByteSlice
}

func (str *BBFSubTagString) String() string {
	return fmt.Sprintf("%v: %s", str.TagType, str.Value)
}

// NewCircuitRemoteIDTag return a BBF Tag with circuit-id and remote-id sub tag.
// if cid or rid is empty string, then it will not be included
func NewCircuitRemoteIDTag(cid, rid string) *BBFTag {
	bbftag := &BBFTag{}
	if cid != "" {
		bbftag.tags = append(bbftag.tags, &BBFSubTagString{
			BBFSubTagByteSlice: &BBFSubTagByteSlice{
				TagType: BBFSubTagNumCircuitID,
				Value:   []byte(cid),
			},
		})
	}
	if rid != "" {
		bbftag.tags = append(bbftag.tags, &BBFSubTagString{
			BBFSubTagByteSlice: &BBFSubTagByteSlice{
				TagType: BBFSubTagNumRemoteID,
				Value:   []byte(rid),
			},
		})
	}
	return bbftag
}

func createTag(t TagType) Tag {
	switch t {
	case TagTypeACName, TagTypeServiceName, TagTypeGenericError, TagTypeServiceNameError, TagTypeACSystemError:
		return &TagString{
			TagByteSlice: new(TagByteSlice),
		}
	case TagTypeEndOfList:
		return new(TagEndOfList)
	}
	return new(TagByteSlice)
}

func createBBFSubTag(t BBFSubTagNum) Tag {
	switch t {
	case BBFSubTagNumRemoteID, BBFSubTagNumCircuitID:
		return &BBFSubTagString{
			BBFSubTagByteSlice: new(BBFSubTagByteSlice),
		}
	case BBFSubTagActualDataRateUpstream, BBFSubTagActualDataRateDownstream, BBFSubTagMinimumDataRateUpstream, BBFSubTagMinimumDataRateDownstream, BBFSubTagAttainableDataRateUpstream, BBFSubTagAttainableDataRateDownstream, BBFSubTagMaximumDataRateUpstream, BBFSubTagMaximumDataRateDownstream, BBFSubTagMinDataRateUpstreaminlow, BBFSubTagMinimumDataRateDownstreaminlow, BBFSubTagMaxInterleavingDelay, BBFSubTagActualInterleavingUpstreamDelay, BBFSubTagMaximumInterleavingDelay, BBFSubTagActualInterleavingDownstreamDelay:
		return new(BBFSubTagUint32)
	}
	return new(BBFSubTagByteSlice)
}
