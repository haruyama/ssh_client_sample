package org.unixuser.haruyama.ssh.message.channel

import org.unixuser.haruyama.ssh.parser._
import org.unixuser.haruyama.ssh.datatype._
import scala.util.parsing.combinator._

case class WindowAdjust(messageId: SSHByte,  recipientChannel : SSHUInt32,  bytesToAdd : SSHUInt32) {
  //TODO: どこかに定数をまとめる
  assert(messageId.value == 93)
}

object WindowAdjustParser extends ByteParsers {

  lazy val windowAdjust : Parser[WindowAdjust] = byte ~ uint32 ~ uint32 ^^
  {case id~rc~bta => WindowAdjust(id, rc, bta)}

  def parse(bytes : Seq[Byte]) : ParseResult[WindowAdjust] = parse[WindowAdjust](windowAdjust, bytes)
  def parseAll(bytes : Seq[Byte]) : ParseResult[WindowAdjust] = parseAll[WindowAdjust](windowAdjust, bytes)

}
