package org.unixuser.haruyama.ssh.datatype
abstract class SSHDataType {
  def toBytes : Array[Byte]
}
object SSHDataType {
  implicit def toSSHBoolean(b: Boolean) = SSHBoolean(b)
  implicit def toSSHUInt32(l: Long) = SSHUInt32(l)
  implicit def toSSHString(s : String) = SSHString(s.getBytes)
}
