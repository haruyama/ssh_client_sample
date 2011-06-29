package org.unixuser.haruyama.ssh.datatype
import org.scalatest.FunSuite


class SSHUInt32Suite extends FunSuite {

  test("tobytes") {
    assert(SSHUInt32(0L).toBytes === Array[Byte](0, 0, 0, 0))
    assert(SSHUInt32(699921578L).toBytes === Array(0x29, 0xb7, 0xf4, 0xaa).map(_.toByte))
    assert(SSHUInt32(2147483648L).toBytes === Array(0x80, 0, 0, 0).map(_.toByte))
    assert(SSHUInt32(4294967295L).toBytes === Array(255,255,255,255).map(_.toByte))
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

