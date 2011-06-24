import org.scalatest.FunSuite

class UInt32Suite extends FunSuite {
    test("parse") {
      assert(UInt32.parse(Array[Byte](0, 0, 0, 0), 0)._1.value === 0L)
      assert(UInt32.parse(Array[Byte](0, 0, 0, 0), 0)._2 === 4)

      assert(UInt32.parse(Array[Byte](0x29, 0xb7.toByte, 0xf4.toByte, 0xaa.toByte), 0)._1.value === 699921578L)
      assert(UInt32.parse(Array[Byte](0x80.toByte, 0, 0, 0), 0)._1.value === 2147483648L)

      assert(UInt32.parse(Array[Byte](0x80.toByte, 0, 0, 0, 0), 1)._1.value === 0)
      assert(UInt32.parse(Array[Byte](0x80.toByte, 0, 0, 0, 0), 1)._2 === 5)


      intercept[ArrayIndexOutOfBoundsException] {
        UInt32.parse(Array[Byte](0x80.toByte, 0, 0, 0), 1)
      }
    }

    test("tobytearray") {
      assert(new UInt32(0L).toByteArray === Array[Byte](0, 0, 0, 0))
      assert(new UInt32(699921578L).toByteArray === Array[Byte](0x29, 0xb7.toByte, 0xf4.toByte, 0xaa.toByte))
      assert(new UInt32(2147483648L).toByteArray === Array[Byte](0x80.toByte, 0, 0, 0))
    }

    test("no uint32") {
      intercept[AssertionError] {
        new UInt32(-1)
      }
      intercept[AssertionError] {
        new UInt32(4294967296L)
      }
    }

}

