package org.unixuser.haruyama.ssh.datatype
import org.scalatest.FunSuite
import org.unixuser.haruyama.ssh.datatype.SSHDataType.toSSHBoolean

class SSHBooleanSuite extends FunSuite {

  test("tobytes") {
    assert(SSHBoolean(true).toBytes === Array[Byte](1))
    assert(SSHBoolean(false).toBytes === Array[Byte](0))
  }

  test("implicit conversion") {
    assert(true.toBytes === Array[Byte](1))
    assert(false.toBytes === Array[Byte](0))
  }
}

