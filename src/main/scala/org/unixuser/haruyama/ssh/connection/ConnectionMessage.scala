package org.unixuser.haruyama.ssh.connection

import org.unixuser.haruyama.ssh.transport.TransportMessageParser
import org.unixuser.haruyama.ssh.parser._
import org.unixuser.haruyama.ssh.datatype._
import scala.util.parsing.combinator._
import org.unixuser.haruyama.ssh.message.Message

trait ConnectionMessage extends Message

object ConnectionConstant {

  val SSH_MSG_GLOBAL_REQUEST            = SSHByte(80)
  val SSH_MSG_REQUEST_SUCCESS           = SSHByte(81)
  val SSH_MSG_REQUEST_FAILURE           = SSHByte(82)
  val SSH_MSG_CHANNEL_OPEN              = SSHByte(90)
  val SSH_MSG_CHANNEL_OPEN_CONFIRMATION = SSHByte(91)
  val SSH_MSG_CHANNEL_OPEN_FAILURE      = SSHByte(92)
  val SSH_MSG_CHANNEL_WINDOW_ADJUST     = SSHByte(93)
  val SSH_MSG_CHANNEL_DATA              = SSHByte(94)
  val SSH_MSG_CHANNEL_EXTENDED_DATA     = SSHByte(95)
  val SSH_MSG_CHANNEL_EOF               = SSHByte(96)
  val SSH_MSG_CHANNEL_CLOSE             = SSHByte(97)
  val SSH_MSG_CHANNEL_REQUEST           = SSHByte(98)
  val SSH_MSG_CHANNEL_SUCCESS           = SSHByte(99)
  val SSH_MSG_CHANNEL_FAILURE           = SSHByte(100)
}


trait ChannelOpen extends ConnectionMessage
case class ChannelOpenSession(messageId : SSHByte, session: SSHString,  senderChannel : SSHUInt32, initialWindowSize : SSHUInt32,
  maximumPacketSize : SSHUInt32) extends ChannelOpen {
  assert(messageId == ConnectionConstant.SSH_MSG_CHANNEL_OPEN)
  assert(session == SSHString("session".getBytes))
}

case class ChannelOpenConfirmation(messageId: SSHByte, recipientChannel: SSHUInt32,  senderChannel : SSHUInt32, initialWindowSize :
  SSHUInt32, maximumPacketSize: SSHUInt32) extends ConnectionMessage {
  assert(messageId == ConnectionConstant.SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
}

trait ChannelRequest extends ConnectionMessage
case class ChannelRequestExec(messageId : SSHByte, recipientChannel : SSHUInt32, exec : SSHString, wantReply: SSHBoolean, command:
  SSHString) extends ChannelRequest {
  assert(messageId == ConnectionConstant.SSH_MSG_CHANNEL_REQUEST)
  assert(exec == SSHString("exec".getBytes))
}

case class ChannelRequestExitStatus(messageId : SSHByte, recipientChannel : SSHUInt32, exitStatusString: SSHString, wantReply: SSHBoolean, exitStatus: SSHUInt32) extends ChannelRequest {
  assert(messageId == ConnectionConstant.SSH_MSG_CHANNEL_REQUEST)
  assert(exitStatusString == SSHString("exit-status".getBytes))
}

case class ChannelWindowAdjust(messageId : SSHByte, recipientChannel : SSHUInt32, bytesToAdd: SSHUInt32) extends ConnectionMessage {
  assert(messageId == ConnectionConstant.SSH_MSG_CHANNEL_WINDOW_ADJUST)
}

case class ChannelData(messageId: SSHByte, recipient: SSHUInt32, data: SSHString) extends ConnectionMessage {
  assert(messageId == ConnectionConstant.SSH_MSG_CHANNEL_DATA)
}

case class ChannelEof(messageId: SSHByte, recipient: SSHUInt32) extends ConnectionMessage {
  assert(messageId == ConnectionConstant.SSH_MSG_CHANNEL_EOF)
}

object ConnectionMessageMaker {

  def makeChannelOpenSession(senderChannel : Long, initialWindowSize: Long, maximumPacketSize: Long) = {
    ChannelOpenSession(ConnectionConstant.SSH_MSG_CHANNEL_OPEN, SSHString("session".getBytes), SSHUInt32(senderChannel),
      SSHUInt32(initialWindowSize), SSHUInt32(maximumPacketSize))
  }

  def makeChannelRequestExec(recipientChannel: Long, command : String) ={
    ChannelRequestExec(ConnectionConstant.SSH_MSG_CHANNEL_REQUEST, SSHUInt32(recipientChannel), SSHString("exec".getBytes),
      SSHBoolean(false), SSHString(command.getBytes("UTF-8")))
  }
}


class ConnectionMessageParser extends TransportMessageParser {
  lazy val channelOpenConfirmation = messageId(ConnectionConstant.SSH_MSG_CHANNEL_OPEN_CONFIRMATION) ~ uint32 ~ uint32 ~ uint32 ~ uint32 ^^
  {case id~rc~sc~iws~mps => ChannelOpenConfirmation(id, rc, sc, iws, mps)}

  lazy val channelWindowAdjust = messageId(ConnectionConstant.SSH_MSG_CHANNEL_WINDOW_ADJUST) ~ uint32 ~ uint32 ^^
  {case id~rc~bta => ChannelWindowAdjust(id, rc, bta)}

  lazy val channelData = messageId(ConnectionConstant.SSH_MSG_CHANNEL_DATA) ~ uint32 ~ string ^^
  {case id~rc~data => ChannelData(id, rc, data)}

  lazy val channelEof = messageId(ConnectionConstant.SSH_MSG_CHANNEL_EOF) ~ uint32 ^^
  {case id~rc => ChannelEof(id, rc)}

  lazy val channelExitStatus = messageId(ConnectionConstant.SSH_MSG_CHANNEL_REQUEST) ~ uint32 ~ string ~ boolean ~ uint32 ^^
  {case id~rc~s~wr~es => ChannelRequestExitStatus(id, rc, s, wr, es)}


  lazy val connectionMessage = transportMessage | channelOpenConfirmation | channelWindowAdjust | channelData | channelEof |
  channelExitStatus

  override def parse(bytes : Seq[Byte]) : ParseResult[Message] = parse[Message](connectionMessage, bytes)
  override def parseAll(bytes : Seq[Byte]) : ParseResult[Message] = parseAll[Message](connectionMessage, bytes)

}
