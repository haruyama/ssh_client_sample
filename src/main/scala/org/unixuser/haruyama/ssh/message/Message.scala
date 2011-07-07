package org.unixuser.haruyama.ssh.message

import org.unixuser.haruyama.ssh.datatype.SSHDataType
import scala.collection.mutable.ArrayBuffer

trait Message extends Product {
  def toBytes() : Array[Byte] = toBytes(this.productIterator)

  private def toBytes(s : TraversableOnce[Any]) : Array[Byte] = {
    val arrayBuffer = new ArrayBuffer[Byte]
    addArrayBuffer(s, arrayBuffer)
    arrayBuffer.toArray
  }

  private def addArrayBuffer(s : TraversableOnce[Any], arrayBuffer : ArrayBuffer[Byte]) {
    s.foreach { e =>
      e match {
        case t: SSHDataType => {
          arrayBuffer ++= t.toBytes
        }
        case to: TraversableOnce[_] => addArrayBuffer(to, arrayBuffer)
        case _ => throw new IllegalArgumentException
      }
    }
  }
}
