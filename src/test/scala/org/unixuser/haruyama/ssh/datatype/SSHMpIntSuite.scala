package org.unixuser.haruyama.ssh.datatype
import org.scalatest.FunSuite


class SSHMpIntSuite extends FunSuite {

  test("tobytes") {
    assert(SSHMpInt(java.math.BigInteger.ZERO).toBytes === Array[Byte](0, 0, 0, 0))
    assert(SSHMpInt(new java.math.BigInteger("0")).toBytes === Array[Byte](0, 0, 0, 0))
    assert(SSHMpInt(new java.math.BigInteger("9a378f9b2e332a7", 16)).toBytes === Array(0, 0, 0, 0x8, 0x9, 0xa3, 0x78, 0xf9, 0xb2,
      0xe3, 0x32, 0xa7).map(_.toByte))
    assert(SSHMpInt(new java.math.BigInteger("80", 16)).toBytes === Array(0, 0, 0, 0x2, 0, 0x80).map(_.toByte))
    assert(SSHMpInt(new java.math.BigInteger("-1234", 16)).toBytes === Array(0, 0, 0, 0x2, 0xed, 0xcc).map(_.toByte))
    assert(SSHMpInt(new java.math.BigInteger("-deadbeef", 16)).toBytes === Array(0, 0, 0, 0x5, 0xff, 0x21, 0x52, 0x41, 0x11).map(_.toByte))

  }


}

