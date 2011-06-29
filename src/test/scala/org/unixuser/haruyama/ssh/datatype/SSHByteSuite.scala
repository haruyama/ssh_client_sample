package org.unixuser.haruyama.ssh.datatype
import org.scalatest.FunSuite


class SSHByteSuite extends FunSuite {

  test("tobytes") {
    assert(SSHByte(0).toBytes === Array[Byte](0))
    assert(SSHByte(127).toBytes === Array[Byte](127))
    assert(SSHByte(255).toBytes === Array[Byte](0xff.toByte))
  }

  test("no byte") {
    intercept[AssertionError] {
      SSHByte(-1)
  }
  intercept[AssertionError] {
    SSHByte(256)
    }
  }

}

