package org.unixuser.haruyama.ssh.datatype
import org.scalatest.FunSuite


class SSHBooleanSuite extends FunSuite {

  test("tobytes") {
    assert(SSHBoolean(true).toBytes === Array[Byte](1))
    assert(SSHBoolean(false).toBytes === Array[Byte](0))
  }
}

