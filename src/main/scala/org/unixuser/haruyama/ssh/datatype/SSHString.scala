package org.unixuser.haruyama.ssh.datatype

case class SSHString(value: String) extends SSHDataType {

  override def toBytes: Array[Byte] = {
    val bytes= new Array[Byte](4 + value.length)
    SSHUInt32(value.length).toBytes.copyToArray(bytes, 0)
    value.getBytes.copyToArray(bytes, 4)
    bytes
  }
}

