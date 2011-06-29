package org.unixuser.haruyama.ssh.datatype
abstract class SSHDataType {
  def toBytes : Array[Byte]
}
