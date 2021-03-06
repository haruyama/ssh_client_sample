package org.unixuser.haruyama.ssh.parser

import scala.util.parsing.combinator._

import org.unixuser.haruyama.ssh.datatype._
import org.unixuser.haruyama.ssh.message.Message

trait ByteParsers extends Parsers {
  type Elem = Byte

  def toSSHBoolean(byte: Byte) : SSHBoolean = {
    if (byte == 0) {
      return SSHBoolean(false)
    }
    return SSHBoolean(true)
  }

  protected def toSSHByte(byte: Byte) : SSHByte = {
    SSHByte((byte & 0xff).toShort)
  }

  protected def toSSHString(bytes: Seq[Byte]) : SSHString = {
    SSHString(bytes.toArray)
  }

  protected def toSSHUInt32(bytes: Seq[Byte]) : SSHUInt32 = {
    SSHUInt32(((bytes(0) & 0xff).toLong << 24) + ((bytes(1) & 0xff).toLong << 16) + ((bytes(2) & 0xff).toLong << 8) + (bytes(3) & 0xff).toLong)
  }

  protected def toSSHNameList(bytes: Seq[Byte]) : SSHNameList= {
    SSHNameList(new String(bytes.toArray, "US-ASCII").split(","))
  }

  protected def toSSHMpInt(bytes: Seq[Byte]) : SSHMpInt = {
    SSHMpInt(new java.math.BigInteger(bytes.toArray))
  }

  protected lazy val elem: Parser[Elem] = elem("elem", _ => true)
  protected lazy val boolean : Parser[SSHBoolean] = elem ^^ toSSHBoolean
  protected lazy val byte : Parser[SSHByte] = elem ^^ toSSHByte
  protected lazy val uint32: Parser[SSHUInt32] = repN(4, elem) ^^ toSSHUInt32
  //toInt のために完全に仕様通りではない
  protected lazy val string: Parser[SSHString] = uint32 >> (l => repN(l.value.toInt, elem)) ^^ toSSHString
  protected lazy val namelist: Parser[SSHNameList] = uint32 >> (l => repN(l.value.toInt, elem)) ^^ toSSHNameList
  protected lazy val mpint: Parser[SSHMpInt] = uint32 >> (l => repN(l.value.toInt, elem)) ^^ toSSHMpInt

  def parse[T](p: Parser[T], in: Input): ParseResult[T] = p(in)
  def parse[T](p: Parser[T], bytes: Seq[Byte]): ParseResult[T] = parse(p, new ByteReader(bytes))
  def parseAll[T](p: Parser[T], bytes: Seq[Byte]): ParseResult[T] = parse(phrase(p), new ByteReader(bytes))
}

abstract class MessageParser extends ByteParsers {
  protected def messageId(id : SSHByte)  : Parser[SSHByte] = {
    accept(id.value.toByte) ^^ toSSHByte
  }

  protected def specifiedString(s: String) : Parser[SSHString] = {
    val sshStr = SSHString(s.getBytes)
    acceptSeq(sshStr.toBytes) ^^ {_ => sshStr}
  }
  def parse(bytes: Seq[Byte]) : ParseResult[Message]
  def parseAll(bytes: Seq[Byte]) : ParseResult[Message]
}
