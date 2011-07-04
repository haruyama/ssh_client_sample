package org.unixuser.haruyama.ssh.transport

import org.unixuser.haruyama.ssh.datatype.SSHUInt32
import org.unixuser.haruyama.ssh.message.Message
import scala.collection.mutable.ArrayBuffer
import java.security.SecureRandom
import java.io._
import ch.ethz.ssh2.crypto.KeyMaterial
import ch.ethz.ssh2.crypto.cipher.BlockCipher
import ch.ethz.ssh2.crypto.cipher.BlockCipherFactory
import ch.ethz.ssh2.crypto.digest.MAC
import java.math.BigInteger


class SequenceNumbers {
  //本来はoverflowする前にrekeyする この実装ではrekeyを扱わない
  var recvSeqNumber = 0
  var sendSeqNumber = 0
}


abstract class Transport(i: InputStream, o: OutputStream, p: TransportMessageParser, seqNumbers : SequenceNumbers) {
  val in  = new BufferedInputStream(i)
  val out = new BufferedOutputStream(o)
  var parser = p
  protected def recvMessageBytes() : Array[Byte]

  def recvMessage() : Message = {
    val bytes : Array[Byte] = recvMessageBytes()
    seqNumbers.recvSeqNumber += 1
    val result = parser.parseAll(bytes)
    if (!result.successful) {
      throw new RuntimeException
    }
    result.get
  }

  protected def sendMessageBytes(bytes: Array[Byte])
  def sendMessage(message: Message) {
    sendMessageBytes(message.toBytes)
    seqNumbers.sendSeqNumber += 1
  }

  protected def parseLength(bytes: Array[Byte]) : Int = {
    val l = ((bytes(0) & 0xff).toLong << 24) + ((bytes(1) & 0xff).toLong << 16) + ((bytes(2) & 0xff).toLong << 8) + (bytes(3) & 0xff).toLong
    l.toInt
  }

  protected def packPayload(message: Array[Byte]) : Array[Byte] = {
    val remainder = (1 + message.size + 4) % 16

    val padding_length =
      if (remainder > 4) {
        32 - remainder
      } else {
        16 - remainder
      }

    val packet_length = message.size + padding_length + 1
    val arrayBuffer = new ArrayBuffer[Byte](4 + packet_length)

    val random = new SecureRandom
    val padding = new Array[Byte](padding_length)
    random.nextBytes(padding);

    arrayBuffer ++= SSHUInt32(packet_length).toBytes
    arrayBuffer += ((padding_length) & 0xff).toByte
    arrayBuffer ++= message
    arrayBuffer ++= padding

    arrayBuffer.toArray
  }
}

class UnencryptedTransport(i: InputStream, o: OutputStream, p: TransportMessageParser, seqNumbers: SequenceNumbers) extends 
Transport(i, o, p, seqNumbers) {

  override def recvMessageBytes() : Array[Byte] = {
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

  override def sendMessageBytes(bytes: Array[Byte]) {
    val packet = packPayload(bytes)
    out.write(packet)
    out.flush
  }
}

class EncryptedTransport(i: InputStream, o: OutputStream, p: TransportMessageParser, sessionId: Array[Byte], h : Array[Byte], k : BigInteger, seqNumbers: SequenceNumbers) extends Transport(i, o, p, seqNumbers) {
  // 鍵の再生成の際には古いsessionIdが存在するが， この実装では利用しない
  // この実装では暗号とMACは決め打ちなのでサイズも決め打ち
  val km = KeyMaterial.create("SHA1", h, k, sessionId, 16, 16, 20, 16, 16, 20)
  val cipherC2S = BlockCipherFactory.createCipher("aes128-ctr", true, km.enc_key_client_to_server, km.initial_iv_client_to_server)
  val cipherS2C = BlockCipherFactory.createCipher("aes128-ctr", true, km.enc_key_server_to_client, km.initial_iv_server_to_client)
  val macC2S    = new MAC("hmac-sha1", km.integrity_key_client_to_server)
  val macS2C    = new MAC("hmac-sha1", km.integrity_key_server_to_client)

  override def recvMessageBytes() : Array[Byte] = {
    val buf = new Array[Byte](16)
    if (in.read(buf, 0, 16) == -1) {
      throw new RuntimeException
    }
    val firstDecrptedBlock = new Array[Byte](16)

    cipherS2C.transformBlock(buf, 0, firstDecrptedBlock, 0)

    val length = parseLength(firstDecrptedBlock) + 4
    var offset = 16
    val decryptedPacket = new Array[Byte](length)
    firstDecrptedBlock.copyToArray(decryptedPacket, 0)

    while (offset < length) {
      if (in.read(buf, 0, 16) == -1) {
        throw new RuntimeException
      }
      cipherS2C.transformBlock(buf, 0, decryptedPacket, offset)
      offset += 16
    }

    val sentMac = new Array[Byte](20)
    if (in.read(sentMac, 0, 20) == -1) {
        throw new RuntimeException
    }


    val mac = new Array[Byte](20)
    macS2C.initMac(seqNumbers.recvSeqNumber)
    macS2C.update(decryptedPacket, 0, decryptedPacket.length)
    macS2C.getMac(mac, 0)
    assert(mac sameElements sentMac)

    val message = new Array[Byte](length - 5 - decryptedPacket(4))
    Array.copy(decryptedPacket, 5, message, 0, length -5 - decryptedPacket(4))
    message
  }


  override def sendMessageBytes(bytes: Array[Byte]) {
    val packet = packPayload(bytes)
    val mac = new Array[Byte](20)
    macC2S.initMac(seqNumbers.sendSeqNumber)
    macC2S.update(packet, 0, packet.length)
    macC2S.getMac(mac, 0)

    val encrypted = new Array[Byte](packet.length)
    var offset = 0

    while (offset < packet.length) {
      cipherC2S.transformBlock(packet, offset, encrypted, offset)
      offset += 16
    }

    out.write(encrypted)
    out.write(mac)
    out.flush
  }
}

