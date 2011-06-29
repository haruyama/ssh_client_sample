package org.unixuser.haruyama.ssh.datatype

case class SSHMpInt(value: BigInt) extends SSHDataType {

  override def toBytes: Array[Byte] = {

    if (value == 0) {
      return Array[Byte](0, 0, 0, 0)
    }

    val byteArray = value.toByteArray
    val bytes = new Array[Byte](byteArray.length + 4)
    SSHUInt32(byteArray.length).toBytes.copyToArray(bytes, 0)
    byteArray.copyToArray(bytes, 4)
    bytes
  }
}

