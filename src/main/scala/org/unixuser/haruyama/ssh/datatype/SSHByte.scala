package org.unixuser.haruyama.ssh.datatype

case class SSHByte(value: Short) extends SSHDataType {
  assert(value >= 0)
  assert(value < 256)

  override def toBytes: Array[Byte] = {
    val bytes = Array[Byte](1)
    bytes(0) = (value & 0xff).toByte
    bytes
  }
}

