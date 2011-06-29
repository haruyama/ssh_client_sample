package org.unixuser.haruyama.ssh.datatype
import org.scalatest.FunSuite


class SSHStringSuite extends FunSuite {
  test("tobytes") {
    assert(SSHString("").toBytes === Array[Byte](0, 0, 0, 0))
    assert(SSHString("ssh-userauth").toBytes === Array[Byte](0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104))
  }
}

