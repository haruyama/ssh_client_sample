package org.unixuser.haruyama.ssh.parser

import scala.util.parsing.combinator._

import org.unixuser.haruyama.ssh.datatype._

trait ByteParsers extends Parsers {
  type Elem = Byte

  def toSSHString(bytes: Seq[Byte]) : String = {
    new String(bytes.toArray)
  }

  def toSSHUInt32(bytes: Seq[Byte]) : SSHUInt32 = {
    new SSHUInt32(((bytes(0) & 0xff).toLong << 24) + ((bytes(1) & 0xff).toLong << 16) + ((bytes(2) & 0xff).toLong << 8) + (bytes(3) & 0xff).toLong)
  }

  lazy val anyElem: Parser[Elem] = elem("anyElem", _ => true)
  lazy val byte : Parser[Byte] = anyElem
  lazy val uint32: Parser[SSHUInt32] = repN(4, byte) ^^ toSSHUInt32
  //toInt のために完全に仕様通りではない
  lazy val string: Parser[String] = uint32 >> (l => repN(l.value.toInt, byte)) ^^ toSSHString

  def parse[T](p: Parser[T], in: Input): ParseResult[T] = p(in)
  def parse[T](p: Parser[T], bytes: Seq[Byte]): ParseResult[T] = parse(p, new ByteReader(bytes))
  def parseAll[T](p: Parser[T], bytes: Seq[Byte]): ParseResult[T] = parse(phrase(p), new ByteReader(bytes))
}
