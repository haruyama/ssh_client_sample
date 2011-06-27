package org.unixuser.haruyama.ssh.parser

import scala.util.parsing.combinator._

import org.unixuser.haruyama.ssh.datatype._

trait ByteParsers extends Parsers {
  type Elem = Byte


  lazy val anyElem: Parser[Elem] = elem("anyElem", _ => true)
  lazy val byte : Parser[Byte] = anyElem
  //lazy val uint32: Parser[UInt32] = repN(4, byte) ^^ UInt32.toUInt32
  lazy val uint32: Parser[UInt32] = repN(4, byte) ^^ UInt32.toUInt32

  def parse[T](p: Parser[T], in: Input): ParseResult[T] = p(in)
  def parse[T](p: Parser[T], bytes: Seq[Byte]): ParseResult[T] = parse(p, new ByteReader(bytes))
  def parseAll[T](p: Parser[T], bytes: Seq[Byte]): ParseResult[T] = parse(phrase(p), new ByteReader(bytes))
}
