package org.unixuser.haruyama.ssh.datatype

case class SSHNameList(value: Seq[String]) extends SSHDataType {
  assert(!value.exists(_.contains(",")))

  override def toBytes: Array[Byte] = {
    SSHString((value mkString ",").getBytes("US-ASCII")).toBytes
  }
}

