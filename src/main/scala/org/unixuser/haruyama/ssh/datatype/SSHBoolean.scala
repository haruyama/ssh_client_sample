package org.unixuser.haruyama.ssh.datatype

case class SSHBoolean(value: Boolean) extends SSHDataType {

  override def toBytes: Array[Byte] = {
    val bytes= new Array[Byte](1)
    if (value) {
      bytes(0) = 1
    } else {
      bytes(0) = 0
    }
    bytes
  }
}

