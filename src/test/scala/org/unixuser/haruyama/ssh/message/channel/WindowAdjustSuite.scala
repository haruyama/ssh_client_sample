package org.unixuser.haruyama.ssh.message.channel
import org.scalatest.FunSuite
import org.unixuser.haruyama.ssh.datatype.UInt32

class WindowAdjustSuite extends FunSuite {
    test("parse") {
      assert(WindowAdjustParser.parseAll(Array[Byte](93, 00, 00, 00, 80, 00, 00, 00, 128.toByte)).get === WindowAdjust(93, new UInt32(80L), new
        UInt32(128L)))
    }

}

