package org.unixuser.haruyama.ssh.transport
import org.scalatest.FunSuite
import org.unixuser.haruyama.ssh.datatype._

class TransportMessageSuite extends FunSuite {
    test("parse") {
      assert((new TransportMessageParser).parseAll(Array[Byte](21)).get === 
        TransportMessageMaker.makeNewkeys())
      assert((new TransportMessageParser).parseAll(Array[Byte](5, 00, 00, 00, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104)).get === 
        TransportMessageMaker.makeServiceRequest("ssh-userauth"))
      assert((new TransportMessageParser).parseAll(Array[Byte](5, 00, 00, 00, 00)).get === 
        TransportMessageMaker.makeServiceRequest(""))
    }

    test("ServiceRequest toBytes") {
      assert(TransportMessageMaker.makeNewkeys().toBytes === Array[Byte](21))
      assert(TransportMessageMaker.makeServiceRequest("ssh-userauth").toBytes ===
        Array[Byte](5, 00, 00, 00, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104))
    }

}

