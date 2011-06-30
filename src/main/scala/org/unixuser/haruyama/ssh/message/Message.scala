package org.unixuser.haruyama.ssh.message

import org.unixuser.haruyama.ssh.datatype.SSHDataType
import scala.collection.mutable.ArrayBuffer

abstract class Message {
  def toBytes() :  Array[Byte]

  protected def toBytes(s : TraversableOnce[Any]) :  Array[Byte] = {
    val arrayBuffer = new ArrayBuffer[Byte]
    toBytes(s, arrayBuffer)
    arrayBuffer.toArray
  }

  private def toBytes(s : TraversableOnce[Any], arrayBuffer : ArrayBuffer[Byte]) {
    s.foreach { e =>
      e match {
        case t: SSHDataType => {
          arrayBuffer ++= t.toBytes
        }
        case to: TraversableOnce[Any] => toBytes(to, arrayBuffer)
        case _ => throw new IllegalArgumentException
      }
    }
  }
}
