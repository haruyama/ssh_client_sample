package org.unixuser.haruyama.ssh.transport
import org.scalatest.FunSuite
import org.unixuser.haruyama.ssh.datatype._

class TransportSuite extends FunSuite {

  private def newKeyTest(test: Array[Byte]) {

    assert(test.length === 16)
    assert(test(0) === 0)
    assert(test(1) === 0)
    assert(test(2) === 0)
    assert(test(3) === 12)
    assert(test(4) === 10)
    assert(test(5) === TransportMessageBuilder.buildNewkeys.messageId.value)
  }


  test("packet") {
    val unencryptedTransport = new UnencryptedTransport(null, null)

    newKeyTest(unencryptedTransport.packPayload(TransportMessageBuilder.buildNewkeys.toBytes, 8))
    newKeyTest(unencryptedTransport.packPayload(TransportMessageBuilder.buildNewkeys.toBytes, 16))
  }

}

