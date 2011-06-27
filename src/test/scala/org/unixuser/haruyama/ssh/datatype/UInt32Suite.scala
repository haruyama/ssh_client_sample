package org.unixuser.haruyama.ssh.datatype
import org.scalatest.FunSuite


class UInt32Suite extends FunSuite {
    test("parse") {
      assert(UInt32.toUInt32(Array[Byte](0, 0, 0, 0)).value === 0L)

      assert(UInt32.toUInt32(Array[Byte](0x29, 0xb7.toByte, 0xf4.toByte, 0xaa.toByte)).value === 699921578L)
      assert(UInt32.toUInt32(Array[Byte](0x80.toByte, 0, 0, 0)).value === 2147483648L)

      intercept[ArrayIndexOutOfBoundsException] {
        UInt32.toUInt32(Array[Byte](0x80.toByte, 0, 0))
      }
    }

    test("tobytes") {
      assert(UInt32(0L).toBytes === Array[Byte](0, 0, 0, 0))
      assert(UInt32(699921578L).toBytes === Array[Byte](0x29, 0xb7.toByte, 0xf4.toByte, 0xaa.toByte))
      assert(UInt32(2147483648L).toBytes === Array[Byte](0x80.toByte, 0, 0, 0))
    }

    test("no uint32") {
      intercept[AssertionError] {
        UInt32(-1)
      }
      intercept[AssertionError] {
        UInt32(4294967296L)
      }
    }

}

