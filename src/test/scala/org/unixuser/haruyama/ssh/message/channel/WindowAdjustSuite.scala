package org.unixuser.haruyama.ssh.message.channel
import org.scalatest.FunSuite
import org.unixuser.haruyama.ssh.datatype._

class WindowAdjustSuite extends FunSuite {
    test("parse") {
      assert(WindowAdjustParser.parseAll(Array[Byte](93, 00, 00, 00, 80, 00, 00, 00, 128.toByte)).get === WindowAdjust(SSHByte(93), SSHUInt32(80L), 
        SSHUInt32(128L)))
    }

}

