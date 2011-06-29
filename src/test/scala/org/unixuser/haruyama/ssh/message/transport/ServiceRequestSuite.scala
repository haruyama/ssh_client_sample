package org.unixuser.haruyama.ssh.message.transport
import org.scalatest.FunSuite
import org.unixuser.haruyama.ssh.datatype._

class ServiceRequestSuite extends FunSuite {
    test("parse") {
      assert(ServiceRequestParser.parseAll(Array[Byte](5, 00, 00, 00, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104)).get === 
        ServiceRequest(SSHByte(5), SSHString("ssh-userauth")))
      assert(ServiceRequestParser.parseAll(Array[Byte](5, 00, 00, 00, 00)).get === 
        ServiceRequest(SSHByte(5), SSHString("")))
    }

}

