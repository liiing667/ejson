package json

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestKeyExtraction(t *testing.T) {
	Convey("Key extraction", t, func() {
		Convey("succeeds when given properly-formatted EJSON", func() {
			in := `{"_public_key": "6d79b7e50073e5e66a4581ed08bf1d9a03806cc4648cffeb6df71b5775e5eb08"}`
			expected := [32]byte{109, 121, 183, 229, 0, 115, 229, 230, 106, 69, 129, 237, 8, 191, 29, 154, 3, 128, 108, 196, 100, 140, 255, 235, 109, 247, 27, 87, 117, 229, 235, 8}
			key, err := ExtractPublicKey([]byte(in))
			So(err, ShouldBeNil)
			So(key, ShouldResemble, expected)
		})
		Convey("fails", func() {
			Convey("if key is too short", func() {
				in := `{"_public_key": "6d79b7e50073e5e66a4581ed08bf1d9a03806cc4648cffeb6df71b5775e5eb0"}`
				_, err := ExtractPublicKey([]byte(in))
				So(err, ShouldEqual, ErrPublicKeyInvalid)
			})

			Convey("or if key is invalid hex", func() {
				in := `{"_public_key": "6d79b7e50073e5e66a45t1ed08bf1d9a03806cc4648cffeb6df71b5775e5eb08"}`
				_, err := ExtractPublicKey([]byte(in))
				So(err, ShouldEqual, ErrPublicKeyInvalid)
			})

			Convey("or if key is missing", func() {
				in := `{"nope": "dunno"}`
				_, err := ExtractPublicKey([]byte(in))
				So(err, ShouldEqual, ErrPublicKeyMissing)
			})

			Convey("or if key is duplicated", func() {
				in := "{\n" +
					`"_public_key": "6d79b7e50073e5e66a4581ed08bf1d9a03806cc4648cffeb6df71b5775e5eb08",` + "\n" +
					`"_public_key": "7d79b7e50073e5e66a4581ed08bf1d9a03806cc4648cffeb6df71b5775e5eb08"` + "\n" +
					"}"
				_, err := ExtractPublicKey([]byte(in))
				So(err, ShouldWrap, ErrPublicKeyDuplicate)
				So(err.Error(), ShouldContainSubstring, "line 3")
			})

			Convey("or if the document is truncated", func() {
				in := `{"_public_key": "6d79b7e50073e5e66a4581ed08bf1d9a03806cc4648cffeb6df71b5775e5eb08"`
				_, err := ExtractPublicKey([]byte(in))
				So(err, ShouldNotBeNil)
			})
		})
	})
}
