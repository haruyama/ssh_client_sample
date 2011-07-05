package org.unixuser.haruyama.ssh.transport
import org.scalatest.FunSuite
import org.unixuser.haruyama.ssh.datatype._

class TransportMessageSuite extends FunSuite {
    test("parse") {
      assert((new TransportMessageParser).parseAll(Array[Byte](21)).get ===
        TransportMessageBuilder.buildNewkeys())
      assert((new TransportMessageParser).parseAll(Array[Byte](5, 00, 00, 00, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104)).get ===
        TransportMessageBuilder.buildServiceRequest("ssh-userauth"))
      assert((new TransportMessageParser).parseAll(Array[Byte](5, 00, 00, 00, 00)).get ===
        TransportMessageBuilder.buildServiceRequest(""))
    }

    test("ServiceRequest toBytes") {
      assert(TransportMessageBuilder.buildNewkeys().toBytes === Array[Byte](21))
      assert(TransportMessageBuilder.buildServiceRequest("ssh-userauth").toBytes ===
        Array[Byte](5, 00, 00, 00, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104))
    }

}

