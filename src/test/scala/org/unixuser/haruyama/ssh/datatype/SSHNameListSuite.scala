package org.unixuser.haruyama.ssh.datatype
import org.scalatest.FunSuite


class SSHNamedListSuite extends FunSuite {

  test("tobytes") {
    assert(SSHNameList(List()).toBytes === Array[Byte](0,0,0,0))
    assert(SSHNameList(List("zlib")).toBytes === Array(0,0,0,4, 0x7a, 0x6c, 0x69, 0x62).map(_.toByte))
    assert(SSHNameList(List("zlib", "none")).toBytes === Array(0,0,0,9, 0x7a, 0x6c, 0x69, 0x62, 0x2c, 0x6e, 0x6f, 0x6e, 0x65).map(_.toByte))
  }

  test("no namedlist") {
    intercept[AssertionError] {
      SSHNameList(List("a,"))
    }
  }

}

