package org.unixuser.haruyama.ssh.message.transport

import org.unixuser.haruyama.ssh.parser._
import org.unixuser.haruyama.ssh.datatype._
import scala.util.parsing.combinator._

case class ServiceRequest(messageId: Short, serviceName : String) {
  assert(messageId == 5)
}

object ServiceRequestParser extends ByteParsers {

  lazy val windowAdjust : Parser[ServiceRequest] = byte ~ string ^^
  {case id~name => new ServiceRequest(id, name)}

  def parse(bytes : Seq[Byte]) : ParseResult[ServiceRequest] = parse[ServiceRequest](windowAdjust, bytes)
  def parseAll(bytes : Seq[Byte]) : ParseResult[ServiceRequest] = parseAll[ServiceRequest](windowAdjust, bytes)

}


