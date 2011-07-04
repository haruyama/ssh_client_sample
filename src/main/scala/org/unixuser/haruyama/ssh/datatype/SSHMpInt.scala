package org.unixuser.haruyama.ssh.datatype

import scala.collection.mutable.ArrayBuffer
import java.math.BigInteger

case class SSHMpInt(value: BigInteger) extends SSHDataType {

  override def toBytes: Array[Byte] = {

    if (value == BigInteger.ZERO) {
      return Array[Byte](0, 0, 0, 0)
    }

    val byteArray = value.toByteArray
    val arrayBuffer = new ArrayBuffer[Byte](4 + byteArray.length)
    List(SSHUInt32(byteArray.length).toBytes, byteArray).foreach { e =>
      arrayBuffer ++= e
    }
    arrayBuffer.toArray
  }
}

