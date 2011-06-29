package org.unixuser.haruyama.ssh.datatype
import scala.collection.mutable.ArrayBuffer

case class SSHString(value: String) extends SSHDataType {

  override def toBytes: Array[Byte] = {
    val byteArray = value.getBytes
    val arrayBuffer = new ArrayBuffer[Byte](4 + byteArray.length)
    arrayBuffer ++= SSHUInt32(byteArray.length).toBytes
    arrayBuffer ++= byteArray
    arrayBuffer.toArray
  }
}

