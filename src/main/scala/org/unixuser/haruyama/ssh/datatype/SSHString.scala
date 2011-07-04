package org.unixuser.haruyama.ssh.datatype
import scala.collection.mutable.ArrayBuffer

case class SSHString(value: Array[Byte]) extends SSHDataType {

  override def toBytes: Array[Byte] = {
    val bytes = new Array[Byte](4 + value.length)
    SSHUInt32(value.length).toBytes.copyToArray(bytes, 0)
    value.copyToArray(bytes, 4)
    bytes
  }

  override def equals(that: Any) = that match {
    case other: SSHString => new String(value) == new String(other.value)
    case _ => false
  }

  override def hashCode() = {
    new String(value).hashCode
  }

  override def toString = {
    "SSHString(\"" + new String(value) + "\")"
  }

}
