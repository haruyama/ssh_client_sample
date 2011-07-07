package org.unixuser.haruyama.ssh.transport

import scala.collection.mutable.ArrayBuffer

import org.unixuser.haruyama.ssh.datatype.SSHUInt32
import org.unixuser.haruyama.ssh.message.Message
import org.unixuser.haruyama.ssh.parser.MessageParser

import java.security.SecureRandom
import java.io._
import java.math.BigInteger

import ch.ethz.ssh2.crypto.KeyMaterial
import ch.ethz.ssh2.crypto.cipher.BlockCipher
import ch.ethz.ssh2.crypto.cipher.BlockCipherFactory
import ch.ethz.ssh2.crypto.digest.MAC


class TransportManager(i: InputStream, o: OutputStream) {
  private var transport : Transport = new UnencryptedTransport(i, o)
  private var sessionId : Option[Array[Byte]] = None
  private val transportParser = new TransportMessageParser
  private var overlayParser : Option[MessageParser] = None
  private var recvSeqNumber : Long = 0
  private var sendSeqNumber : Long = 0

  val UINT32_MAX = 4294967295L

  def setOverlayParser(p : MessageParser) {
    overlayParser = Some(p)
  }

  def clearOverlayParser() {
    overlayParser = None
  }

  def changeKey(h : Array[Byte], k : BigInteger) {
    transport =
      sessionId match {
        case Some(sid) => new EncryptedTransport(i, o, sid, h, k)
        case None      =>
          sessionId = Some(h.clone)
          new EncryptedTransport(i, o, h, h, k)
     }
  }


  def parseMessage(bytes: Array[Byte]) : Message = {
    val transportResult = transportParser.parseAll(bytes)
    if (transportResult.successful) {
      // SSH_MSG_DISCONNECT, SSH_MSG_IGNORE, SSH_MSG_DEBUG はここで処理し伝播させないほうがよさそう
      // ここでは省略する
      return transportResult.get
    }
    if (overlayParser.isEmpty) {
      throw new RuntimeException
    }
    val overlayResult = overlayParser.get.parseAll(bytes)

    if (!overlayResult.successful) {
      throw new RuntimeException
    }
    overlayResult.get
  }



  def recvMessage() : Message = {
    val bytes : Array[Byte] = transport.recvMessageBytes(recvSeqNumber)
    recvSeqNumber += 1
    if (recvSeqNumber > UINT32_MAX) recvSeqNumber = 0

    parseMessage(bytes)
  }

  def sendMessage(message: Message) {
    transport.sendMessageBytes(message.toBytes, sendSeqNumber)
    sendSeqNumber += 1
    if (sendSeqNumber > UINT32_MAX) sendSeqNumber = 0
  }

}



abstract class Transport(i: InputStream, o: OutputStream) {
  protected val in  = new BufferedInputStream(i)
  protected val out = new BufferedOutputStream(o)

  val UINT32_SIZE = 4
  val MINIMUM_PADDING_LENGTH = 4

  def recvMessageBytes(recvSeqNumber : Long) : Array[Byte]

  def sendMessageBytes(bytes: Array[Byte], sendSeqNumber: Long)
  protected def parseLength(bytes: Array[Byte]) : Int = {
    val l = ((bytes(0) & 0xff).toLong << 24) + ((bytes(1) & 0xff).toLong << 16) + ((bytes(2) & 0xff).toLong << 8) + (bytes(3) & 0xff).toLong
    l.toInt
  }

  protected def packPayload(message: Array[Byte], blockSize: Int) : Array[Byte] = {
    val remainder = (1 + message.size + UINT32_SIZE) % blockSize

    val padding_length =
      if (remainder > (blockSize - MINIMUM_PADDING_LENGTH)) {
        blockSize * 2 - remainder
      } else {
        blockSize - remainder
      }

    val packet_length = message.size + padding_length + 1
    val arrayBuffer = new ArrayBuffer[Byte](UINT32_SIZE + packet_length)

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

private class UnencryptedTransport(i: InputStream, o: OutputStream) extends
Transport(i, o) {

  override def recvMessageBytes(recvSeqNumber: Long) : Array[Byte] = synchronized {
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

  override def sendMessageBytes(bytes: Array[Byte], sendSeqNumber: Long) = synchronized {
    val packet = packPayload(bytes, 8)
    out.write(packet)
    out.flush
  }
}

private class EncryptedTransport(i: InputStream, o: OutputStream, sessionId: Array[Byte], h : Array[Byte], k : BigInteger) extends Transport(i, o) {
  // この実装では暗号とMACは決め打ちなのでサイズも決め打ち
  val CIPHERC2S_KEY_SIZE   = 16
  val CIPHERC2S_BLOCK_SIZE = 16

  val CIPHERS2C_KEY_SIZE = 16
  val CIPHERS2C_BLOCK_SIZE = 16

  val MACC2S_SIZE = 20
  val MACS2C_SIZE = 20

  private val km = KeyMaterial.create("SHA1", h, k, sessionId, CIPHERC2S_KEY_SIZE, CIPHERC2S_BLOCK_SIZE, MACC2S_SIZE, CIPHERS2C_KEY_SIZE,
    CIPHERS2C_BLOCK_SIZE, MACS2C_SIZE)
  private val cipherC2S = BlockCipherFactory.createCipher("aes128-ctr", true, km.enc_key_client_to_server, km.initial_iv_client_to_server)
  private val cipherS2C = BlockCipherFactory.createCipher("aes128-ctr", true, km.enc_key_server_to_client, km.initial_iv_server_to_client)
  private val macC2S    = new MAC("hmac-sha1", km.integrity_key_client_to_server)
  private val macS2C    = new MAC("hmac-sha1", km.integrity_key_server_to_client)

  override def recvMessageBytes(recvSeqNumber: Long) : Array[Byte] = synchronized {
    val buf = new Array[Byte](CIPHERS2C_BLOCK_SIZE)
    if (in.read(buf, 0, CIPHERS2C_BLOCK_SIZE) == -1) {
      throw new RuntimeException
    }
    val firstDecrptedBlock = new Array[Byte](CIPHERS2C_BLOCK_SIZE)

    cipherS2C.transformBlock(buf, 0, firstDecrptedBlock, 0)

    val length = parseLength(firstDecrptedBlock) + 4
    var offset = CIPHERS2C_BLOCK_SIZE
    val decryptedPacket = new Array[Byte](length)
    firstDecrptedBlock.copyToArray(decryptedPacket, 0)

    while (offset < length) {
      if (in.read(buf, 0, CIPHERS2C_BLOCK_SIZE) == -1) {
        throw new RuntimeException
      }
      cipherS2C.transformBlock(buf, 0, decryptedPacket, offset)
      offset += CIPHERS2C_BLOCK_SIZE
    }

    val sentMac = new Array[Byte](MACS2C_SIZE)
    if (in.read(sentMac, 0, MACS2C_SIZE) == -1) {
        throw new RuntimeException
    }


    val mac = new Array[Byte](MACS2C_SIZE)
    macS2C.initMac(recvSeqNumber.toInt)
    macS2C.update(decryptedPacket, 0, decryptedPacket.length)
    macS2C.getMac(mac, 0)
    assert(mac sameElements sentMac)

    val message = new Array[Byte](length - 5 - decryptedPacket(4))
    Array.copy(decryptedPacket, 5, message, 0, length -5 - decryptedPacket(4))
    message
  }


  override def sendMessageBytes(bytes: Array[Byte], sendSeqNumber : Long) = synchronized {
    val packet = packPayload(bytes, CIPHERC2S_BLOCK_SIZE)
    val mac = new Array[Byte](MACC2S_SIZE)
    macC2S.initMac(sendSeqNumber.toInt)
    macC2S.update(packet, 0, packet.length)
    macC2S.getMac(mac, 0)

    val encrypted = new Array[Byte](packet.length)
    var offset = 0

    while (offset < packet.length) {
      cipherC2S.transformBlock(packet, offset, encrypted, offset)
      offset += CIPHERC2S_BLOCK_SIZE
    }

    out.write(encrypted)
    out.write(mac)
    out.flush
  }
}

