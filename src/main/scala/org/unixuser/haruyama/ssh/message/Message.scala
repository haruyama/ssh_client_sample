package org.unixuser.haruyama.ssh.message

import org.unixuser.haruyama.ssh.datatype.SSHDataType
//import scala.collection.mutable.ArrayBuilder
import scala.collection.mutable.ArrayBuilder

trait Message extends Product {
  def toBytes() : Array[Byte] = toBytes(this.productIterator)

  private def toBytes(s : TraversableOnce[Any]) : Array[Byte] = {
    val arrayBuilder = ArrayBuilder.make[Byte]
    addArrayBuilder(s, arrayBuilder)
    arrayBuilder.result
  }

  private def addArrayBuilder(s : TraversableOnce[Any], arrayBuilder : ArrayBuilder[Byte]) {
    s.foreach {
      case t: SSHDataType => {
        arrayBuilder ++= t.toBytes
      }
      case to: TraversableOnce[_] => addArrayBuilder(to, arrayBuilder)
      case _ => throw new IllegalArgumentException
    }
  }
}
