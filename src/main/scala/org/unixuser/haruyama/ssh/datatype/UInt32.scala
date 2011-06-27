package org.unixuser.haruyama.ssh.datatype

case class UInt32(value: Long) extends Type {
  assert(value >= 0)
  assert(value < 4294967296L)


  def toBytes: Array[Byte] = {
    val bytes= new Array[Byte](4)
    bytes(0) = ((value >> 24) & 0xff).toByte
    bytes(1) = ((value >> 16) & 0xff).toByte
    bytes(2) = ((value >> 8) & 0xff).toByte
    bytes(3) = (value & 0xff).toByte
    bytes
  }
}

object UInt32 {
  def toUInt32(bytes: Seq[Byte]) : UInt32 = {
    new UInt32(((bytes(0) & 0xff).toLong << 24) + ((bytes(1) & 0xff).toLong << 16) + ((bytes(2) & 0xff).toLong << 8) + (bytes(3) & 0xff).toLong)
  }
}
