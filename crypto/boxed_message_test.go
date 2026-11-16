package crypto

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestBoxedMessageRoundtripping(t *testing.T) {
	Convey("BoxedMessage", t, func() {
		pk := [32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
		nonce := [24]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
		wire := "EJ[1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:AgICAgICAgICAgICAgICAgICAgICAgIC:AwMD]"
		Convey("Dump", func() {
			bm := boxedMessage{
				SchemaVersion:   1,
				EncrypterPublic: pk,
				Nonce:           nonce,
				Box:             []byte{3, 3, 3},
			}
			So(string(bm.Dump()), ShouldEqual, wire)
		})
		Convey("Load", func() {
			bm := boxedMessage{}
			err := bm.Load([]byte(wire))
			So(err, ShouldBeNil)
			So(bm.EncrypterPublic, ShouldResemble, pk)
			So(bm.Nonce, ShouldResemble, nonce)
			So(bm.Box, ShouldResemble, []byte{3, 3, 3})
		})

		Convey("IsBoxedMessage", func() {
			So(IsBoxedMessage([]byte(wire)), ShouldBeTrue)
			So(IsBoxedMessage([]byte("nope")), ShouldBeFalse)
			So(IsBoxedMessage([]byte("EJ[]")), ShouldBeFalse)
			So(IsBoxedMessage([]byte("EJ[1:12345678901234567890123456789012345678901234:12345678901234567890123456789012:a]")), ShouldBeFalse)
		})

		Convey("Load fails closed", func() {
			Convey("on unknown schema version", func() {
				bm := boxedMessage{}
				err := bm.Load([]byte("EJ[2:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:AgICAgICAgICAgICAgICAgICAgICAgIC:AwMD]"))
				So(err, ShouldWrap, ErrUnknownSchemaVersion)
			})
			Convey("on non-numeric schema version", func() {
				bm := boxedMessage{}
				err := bm.Load([]byte("EJ[x:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:AgICAgICAgICAgICAgICAgICAgICAgIC:AwMD]"))
				So(err, ShouldNotBeNil)
			})
			Convey("on truncated base64", func() {
				bm := boxedMessage{}
				err := bm.Load([]byte("EJ[1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE:AgICAgICAgICAgICAgICAgICAgICAgIC:AwMD]"))
				So(err, ShouldNotBeNil)
			})
			Convey("on invalid base64", func() {
				bm := boxedMessage{}
				err := bm.Load([]byte("EJ[1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ!=:AgICAgICAgICAgICAgICAgICAgICAgIC:AwMD]"))
				So(err, ShouldNotBeNil)
			})
			Convey("on a wrong-length public key", func() {
				bm := boxedMessage{}
				err := bm.Load([]byte("EJ[1:AQEBAQE=:AgICAgICAgICAgICAgICAgICAgICAgIC:AwMD]"))
				So(err, ShouldNotBeNil)
			})
			Convey("on a missing field", func() {
				bm := boxedMessage{}
				err := bm.Load([]byte("EJ[1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:AgICAgICAgICAgICAgICAgICAgICAgIC]"))
				So(err, ShouldNotBeNil)
			})
			Convey("on an empty box", func() {
				bm := boxedMessage{}
				err := bm.Load([]byte("EJ[1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:AgICAgICAgICAgICAgICAgICAgICAgIC:]"))
				So(err, ShouldNotBeNil)
			})
			Convey("on a missing envelope", func() {
				bm := boxedMessage{}
				err := bm.Load([]byte("1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:AgICAgICAgICAgICAgICAgICAgICAgIC:AwMD"))
				So(err, ShouldNotBeNil)
			})
		})
	})
}
