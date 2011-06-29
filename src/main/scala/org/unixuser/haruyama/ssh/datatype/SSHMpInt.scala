package org.unixuser.haruyama.ssh.datatype

import scala.collection.mutable.ArrayBuffer

case class SSHMpInt(value: BigInt) extends SSHDataType {

  override def toBytes: Array[Byte] = {

    if (value == 0) {
      return Array[Byte](0, 0, 0, 0)
    }

    val byteArray = value.toByteArray
    val arrayBuffer = new ArrayBuffer[Byte](4 + byteArray.length)
    arrayBuffer ++= SSHUInt32(byteArray.length).toBytes
    arrayBuffer ++= byteArray
    arrayBuffer.toArray
  }
}

