package org.unixuser.haruyama.ssh.transport

import org.unixuser.haruyama.ssh.parser._
import org.unixuser.haruyama.ssh.datatype._
import scala.util.parsing.combinator._
import org.unixuser.haruyama.ssh.message.Message

abstract class TransportMessage extends Message

object TransportConstant {
  val SSH_MSG_DISCONNECT      = SSHByte(1)
  val SSH_MSG_IGNORE          = SSHByte(2)
  val SSH_MSG_UNIMPLEMENTED   = SSHByte(3)
  val SSH_MSG_DEBUG           = SSHByte(4)
  val SSH_MSG_SERVICE_REQUEST = SSHByte(5)
  val SSH_MSG_SERVICE_ACCEPT  = SSHByte(6)
  val SSH_MSG_KEXINIT         = SSHByte(20)
  val SSH_MSG_NEWKEYS         = SSHByte(21)
}

case class ServiceRequest(messageId: SSHByte, serviceName : SSHString) extends TransportMessage {
  assert(messageId == TransportConstant.SSH_MSG_SERVICE_REQUEST)
  override def toBytes() : Array[Byte] = toBytes(this.productIterator)
}

object TransportMessageMaker {
  def makeServiceRequest(serviceName: String) : ServiceRequest = {
    ServiceRequest(TransportConstant.SSH_MSG_SERVICE_REQUEST, SSHString(serviceName))
  }
}

object TransportMessageParser extends ByteParsers {

  lazy val serviceRequest: Parser[ServiceRequest] = byte ~ string ^^
  {case id~name if id == TransportConstant.SSH_MSG_SERVICE_REQUEST => ServiceRequest(id, name)}

  lazy val transportMessage = serviceRequest

  def parse(bytes : Seq[Byte]) : ParseResult[Message] = parse[Message](transportMessage, bytes)
  def parseAll(bytes : Seq[Byte]) : ParseResult[Message] = parseAll[Message](transportMessage, bytes)

}


