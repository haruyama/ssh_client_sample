package org.unixuser.haruyama.ssh.datatype
import org.scalatest.FunSuite
import org.unixuser.haruyama.ssh.datatype.SSHDataType.toSSHString


class SSHStringSuite extends FunSuite {
  test("tobytes") {
    assert(SSHString("".getBytes).toBytes === Array[Byte](0, 0, 0, 0))
  }
  test("implicit conversion") {
    assert("".toBytes === Array[Byte](0, 0, 0, 0))
    assert("ssh-userauth".toBytes === Array[Byte](0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104))
  }
}

