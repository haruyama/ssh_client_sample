package org.unixuser.haruyama.ssh.transport

import org.unixuser.haruyama.ssh.parser._
import org.unixuser.haruyama.ssh.datatype._
import scala.util.parsing.combinator._
import org.unixuser.haruyama.ssh.message.Message
import java.security.SecureRandom

trait TransportMessage extends Message

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


case class Newkeys(messageId: SSHByte) extends TransportMessage {
  assert(messageId == TransportConstant.SSH_MSG_NEWKEYS)
}

case class ServiceRequest(messageId: SSHByte, serviceName : SSHString) extends TransportMessage {
  assert(messageId == TransportConstant.SSH_MSG_SERVICE_REQUEST)
}

case class ServiceAccept(messageId: SSHByte, serviceName : SSHString) extends TransportMessage {
  assert(messageId == TransportConstant.SSH_MSG_SERVICE_ACCEPT)
}

case class Kexinit(messageId: SSHByte, cookie: Seq[SSHByte], kexAlgo: SSHNameList,
  serverHostKeyAlgo: SSHNameList, cipherC2S: SSHNameList,
  cipherS2C: SSHNameList, macC2S: SSHNameList, macS2C : SSHNameList,
  compC2S: SSHNameList, compS2C: SSHNameList, langC2S: SSHNameList,
  langS2C: SSHNameList, firstKexPacketFollows: SSHBoolean, reserved: SSHUInt32)
  extends TransportMessage {
  assert(messageId == TransportConstant.SSH_MSG_KEXINIT)
  assert(cookie.length == 16)
}

object TransportMessageMaker {
  def makeNewkeys() : Newkeys = {
    Newkeys(TransportConstant.SSH_MSG_NEWKEYS)
  }
  def makeServiceRequest(serviceName: String) : ServiceRequest = {
    ServiceRequest(TransportConstant.SSH_MSG_SERVICE_REQUEST, SSHString(serviceName.getBytes("US-ASCII")))
  }
  def makeKexinit(kexAlgo: Seq[String], cookie: Seq[Byte],
  serverHostKeyAlgo: Seq[String], cipherC2S: Seq[String],
  cipherS2C: Seq[String], macC2S: Seq[String], macS2C : Seq[String],
  compC2S: Seq[String], compS2C: Seq[String], langC2S: Seq[String],
  langS2C: Seq[String], firstKexPacketFollows: Boolean) : Kexinit = {

    Kexinit(TransportConstant.SSH_MSG_KEXINIT, cookie.map(e => SSHByte((e & 0xff).toShort)),
      SSHNameList(kexAlgo), SSHNameList(serverHostKeyAlgo), SSHNameList(cipherC2S),
      SSHNameList(cipherS2C), SSHNameList(macC2S), SSHNameList(macS2C),
      SSHNameList(compC2S), SSHNameList(compS2C), SSHNameList(langC2S),
      SSHNameList(langS2C), SSHBoolean(firstKexPacketFollows), SSHUInt32(0))
  }
  def makeKexinit(kexAlgo: Seq[String], 
  serverHostKeyAlgo: Seq[String], cipherC2S: Seq[String],
  cipherS2C: Seq[String], macC2S: Seq[String], macS2C : Seq[String],
  compC2S: Seq[String], compS2C: Seq[String], langC2S: Seq[String],
  langS2C: Seq[String], firstKexPacketFollows: Boolean) : Kexinit = {

    val random = new SecureRandom();
    val cookie = new Array[Byte](16)
    random.nextBytes(cookie);
    makeKexinit(kexAlgo, cookie, serverHostKeyAlgo, cipherC2S, cipherS2C, macC2S, macS2C, compC2S, compS2C, langC2S, langS2C,
      firstKexPacketFollows)
  }
}

class TransportMessageParser extends ByteParsers {

  def messageId(id : SSHByte)  : Parser[SSHByte] = {
    elem("messageId", (b:Byte)  => id.value.toByte == b) ^^ toSSHByte
  }
  lazy val newkeys : Parser[Newkeys] = messageId(TransportConstant.SSH_MSG_NEWKEYS) ^^ {(b :SSHByte)=> Newkeys(b)}

  lazy val serviceRequest: Parser[ServiceRequest] = messageId(TransportConstant.SSH_MSG_SERVICE_REQUEST) ~ string ^^
  {case id~name => ServiceRequest(id, name)}

  lazy val serviceAccept: Parser[ServiceAccept] = messageId(TransportConstant.SSH_MSG_SERVICE_ACCEPT) ~ string ^^
  {case id~name => ServiceAccept(id, name)}


  lazy val kexinit : Parser[Kexinit] = messageId(TransportConstant.SSH_MSG_KEXINIT) ~ repN(16, byte) ~ namelist ~ namelist ~ namelist ~ namelist ~ namelist ~ namelist ~
  namelist ~ namelist ~ namelist ~ namelist ~ boolean ~ uint32 ^^
  {case id~cookie~kex~hostkey~cipherc2s~ciphers2c~macc2s~macs2c~compc2s~comps2c~langc2s~langs2c~first~reserved =>
    Kexinit(id,cookie,kex,hostkey,cipherc2s,ciphers2c,macc2s,macs2c,compc2s,comps2c,langc2s,langs2c,first,reserved)
  }


  lazy val transportMessage = newkeys | serviceRequest | serviceAccept | kexinit

  def parse(bytes : Seq[Byte]) : ParseResult[Message] = parse[Message](transportMessage, bytes)
  def parseAll(bytes : Seq[Byte]) : ParseResult[Message] = parseAll[Message](transportMessage, bytes)

}


