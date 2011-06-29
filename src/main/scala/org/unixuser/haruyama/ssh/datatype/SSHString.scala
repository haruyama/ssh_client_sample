package org.unixuser.haruyama.ssh.datatype
import scala.collection.mutable.ArrayBuffer

case class SSHString(value: String) extends SSHDataType {

  override def toBytes: Array[Byte] = {
    val byteArray = value.getBytes
    val arrayBuffer = new ArrayBuffer[Byte](4 + byteArray.length)
    for (e <- List(SSHUInt32(byteArray.length).toBytes, byteArray)) {
      arrayBuffer ++= e
    }
    arrayBuffer.toArray
  }
}

