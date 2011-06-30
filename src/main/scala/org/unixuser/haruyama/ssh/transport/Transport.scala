package org.unixuser.haruyama.ssh.transport

import org.unixuser.haruyama.ssh.datatype.SSHUInt32
import scala.collection.mutable.ArrayBuffer
import java.security.SecureRandom
import java.io._

abstract class Transport {
  //TODO: contextに依存したrecv/sendMessage
  def recvMessage() : Array[Byte]
  def sendMessage(message: Array[Byte])
  def parseLength(bytes: Array[Byte]) : Int = {
    val l = ((bytes(0) & 0xff).toLong << 24) + ((bytes(1) & 0xff).toLong << 16) + ((bytes(2) & 0xff).toLong << 8) + (bytes(3) & 0xff).toLong
    l.toInt
  }
}

class UnencryptedTransport(in: InputStream, out: OutputStream) extends Transport {
  val bin  = new BufferedInputStream(in)
  val bout = new BufferedOutputStream(out)


  override def recvMessage() : Array[Byte] = {
    val lengthBytes = new Array[Byte](4)
    if (in.read(lengthBytes, 0, 4) == -1) {
      throw new RuntimeException
    }
    val length = parseLength(lengthBytes)
    val padding_length = in.read
    if (padding_length == -1) {
      throw new RuntimeException
    }
    val message = new Array[Byte](length - padding_length - 1)

    if (in.read(message, 0, length - padding_length - 1) == -1) {
      throw new RuntimeException
    }
    val padding = new Array[Byte](padding_length)

    if (in.read(padding, 0, padding_length) == -1) {
      throw new RuntimeException
    }
    message
  }

  override def sendMessage(message: Array[Byte]) {
    val remainder = (1 + message.size + 4) % 16

    val padding_length =
      if (remainder > 4) {
        32 - remainder
      } else {
        16 - remainder
      }

      val packet_length = message.size + padding_length + 1
      val arrayBuffer = new ArrayBuffer[Byte](4 + packet_length)

      val random = new SecureRandom();
      val padding = new Array[Byte](padding_length)
      random.nextBytes(padding);

      arrayBuffer ++= SSHUInt32(padding_length).toBytes
      arrayBuffer += ((padding_length) & 0xff).toByte
      arrayBuffer ++= message
      arrayBuffer ++= padding

      arrayBuffer.toArray
  }
}
