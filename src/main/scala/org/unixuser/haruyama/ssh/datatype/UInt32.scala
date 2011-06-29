package org.unixuser.haruyama.ssh.datatype

case class SSHUInt32(value: Long) extends SSHDataType {
  assert(value >= 0)
  assert(value < 4294967296L)

  override def toBytes: Array[Byte] = {
    val bytes= new Array[Byte](4)
    bytes(0) = ((value >> 24) & 0xff).toByte
    bytes(1) = ((value >> 16) & 0xff).toByte
    bytes(2) = ((value >> 8) & 0xff).toByte
    bytes(3) = (value & 0xff).toByte
    bytes
  }
}

