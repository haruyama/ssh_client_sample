package org.unixuser.haruyama.ssh.datatype
import org.scalatest.FunSuite


class SSHUInt32Suite extends FunSuite {

  test("tobytes") {
    assert(SSHUInt32(0L).toBytes === Array[Byte](0, 0, 0, 0))
    assert(SSHUInt32(699921578L).toBytes === Array[Byte](0x29, 0xb7.toByte, 0xf4.toByte, 0xaa.toByte))
    assert(SSHUInt32(2147483648L).toBytes === Array[Byte](0x80.toByte, 0, 0, 0))
  }

  test("no uint32") {
    intercept[AssertionError] {
      SSHUInt32(-1)
  }
  intercept[AssertionError] {
    SSHUInt32(4294967296L)
    }
  }

}

