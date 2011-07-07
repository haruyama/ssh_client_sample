package org.unixuser.haruyama.ssh.transport

import org.unixuser.haruyama.ssh.parser._
import org.unixuser.haruyama.ssh.datatype._
import scala.util.parsing.combinator._
import org.unixuser.haruyama.ssh.message.Message
import java.math.BigInteger

trait DhExchangeMessage extends Message

object DhExchangeConstant {
  val SSH_MSG_KEXDH_INIT = SSHByte(30)
  val SSH_MSG_KEXDH_REPLY = SSHByte(31)
}

case class KexdhInit(messageId: SSHByte, e: SSHMpInt) extends DhExchangeMessage {
  assert(messageId == DhExchangeConstant.SSH_MSG_KEXDH_INIT)
}

case class KexdhReply(messageId: SSHByte, hostKey : SSHString, f : SSHMpInt, sigOfH : SSHString) extends DhExchangeMessage {
  assert(messageId == DhExchangeConstant.SSH_MSG_KEXDH_REPLY)
}

object DhExchangeMessageBuilder {
  def buildKexdhInit(e: BigInteger) : KexdhInit = {
    KexdhInit(DhExchangeConstant.SSH_MSG_KEXDH_INIT, SSHMpInt(e))
  }
}

class DhExchangeMessageParser extends MessageParser {

  private lazy val kexDhReply = messageId(DhExchangeConstant.SSH_MSG_KEXDH_REPLY) ~ string ~ mpint ~ string ^^ {case id~hostKey~f~sigOfH =>
    KexdhReply(id, hostKey, f, sigOfH)}

  private lazy val dhExchageMessage = kexDhReply

  override def parse(bytes : Seq[Byte]) : ParseResult[Message] = parse[Message](dhExchageMessage, bytes)
  override def parseAll(bytes : Seq[Byte]) : ParseResult[Message] = parseAll[Message](dhExchageMessage, bytes)

}

