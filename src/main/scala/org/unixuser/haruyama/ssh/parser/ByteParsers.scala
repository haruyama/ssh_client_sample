package org.unixuser.haruyama.ssh.parser

import scala.util.parsing.combinator._

import org.unixuser.haruyama.ssh.datatype._

trait ByteParsers extends Parsers {
  type Elem = Byte

  def toSSHBoolean(byte: Byte) : SSHBoolean = {
    if (byte == 0) {
      return SSHBoolean(false)
    } 
    return SSHBoolean(true)

  }

  def toSSHByte(byte: Byte) : SSHByte = {
    SSHByte((byte & 0xff).toShort)
  }

  def toSSHString(bytes: Seq[Byte]) : SSHString = {
    SSHString(new String(bytes.toArray))
  }

  def toSSHUInt32(bytes: Seq[Byte]) : SSHUInt32 = {
    SSHUInt32(((bytes(0) & 0xff).toLong << 24) + ((bytes(1) & 0xff).toLong << 16) + ((bytes(2) & 0xff).toLong << 8) + (bytes(3) & 0xff).toLong)
  }


  def toSSHNamedList(bytes: Seq[Byte]) : SSHNamedList= {
    SSHNamedList(new String(bytes.toArray).split(","))
  }


  lazy val elem: Parser[Elem] = elem("elem", _ => true)
  lazy val boolean : Parser[SSHBoolean] = elem ^^ toSSHBoolean
  lazy val byte : Parser[SSHByte] = elem ^^ toSSHByte
  lazy val uint32: Parser[SSHUInt32] = repN(4, elem) ^^ toSSHUInt32
  //toInt のために完全に仕様通りではない
  lazy val string: Parser[SSHString] = uint32 >> (l => repN(l.value.toInt, elem)) ^^ toSSHString
  lazy val namedlist: Parser[SSHNamedList] = uint32 >> (l => repN(l.value.toInt, elem)) ^^ toSSHNamedList

  def parse[T](p: Parser[T], in: Input): ParseResult[T] = p(in)
  def parse[T](p: Parser[T], bytes: Seq[Byte]): ParseResult[T] = parse(p, new ByteReader(bytes))
  def parseAll[T](p: Parser[T], bytes: Seq[Byte]): ParseResult[T] = parse(phrase(p), new ByteReader(bytes))
}
