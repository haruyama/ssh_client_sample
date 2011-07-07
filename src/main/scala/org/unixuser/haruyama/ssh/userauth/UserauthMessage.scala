package org.unixuser.haruyama.ssh.userauth

import org.unixuser.haruyama.ssh.transport.TransportMessageParser
import org.unixuser.haruyama.ssh.parser._
import org.unixuser.haruyama.ssh.datatype._
import scala.util.parsing.combinator._
import org.unixuser.haruyama.ssh.message.Message
import java.math.BigInteger

trait UserauthMessage extends Message

object UserauthConstant {
  val SSH_MSG_USERAUTH_REQUEST = SSHByte(50)
  val SSH_MSG_USERAUTH_FAILURE = SSHByte(51)
  val SSH_MSG_USERAUTH_SUCCESS = SSHByte(52)
  val SSH_MSG_USERAUTH_BANNER  = SSHByte(53)
}

trait UserauthRequest extends UserauthMessage

case class UserauthRequestPassword(messageId: SSHByte, userName: SSHString, serviceName: SSHString, methodName: SSHString, change: SSHBoolean,
  password: SSHString) extends UserauthRequest {
  assert(messageId == UserauthConstant.SSH_MSG_USERAUTH_REQUEST)
  assert(methodName == SSHString("password".getBytes))
}

case class UserauthFailure(messageId: SSHByte, authentications: SSHNameList, partialSuccess: SSHBoolean) extends UserauthMessage {
  assert(messageId == UserauthConstant.SSH_MSG_USERAUTH_FAILURE)
}
case class UserauthSuccess(messageId: SSHByte) extends UserauthMessage {
  assert(messageId == UserauthConstant.SSH_MSG_USERAUTH_SUCCESS)
}

object UserauthMessageBuilder {
  def buildUserauthRequestPassword(user: String, pass: String) : UserauthRequestPassword = {
    UserauthRequestPassword(UserauthConstant.SSH_MSG_USERAUTH_REQUEST, user, "ssh-connection", "password", false, pass)
  }
}

class UserauthMessageParser extends MessageParser {

  private lazy val userauthFailure = messageId(UserauthConstant.SSH_MSG_USERAUTH_FAILURE) ~ namelist ~ boolean ^^ {case id~auth~ps =>
  UserauthFailure(id, auth, ps)}

  private lazy val userauthSuccess = messageId(UserauthConstant.SSH_MSG_USERAUTH_SUCCESS) ^^ {(b :SSHByte)=> UserauthSuccess(b)}

  private lazy val userauthMessage = userauthFailure | userauthSuccess

  override def parse(bytes : Seq[Byte]) : ParseResult[Message] = parse[Message](userauthMessage, bytes)
  override def parseAll(bytes : Seq[Byte]) : ParseResult[Message] = parseAll[Message](userauthMessage, bytes)
}
