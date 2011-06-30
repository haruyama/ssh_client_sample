package org.unixuser.haruyama.ssh

import org.unixuser.haruyama.ssh.transport._
import java.io._
import java.net.{ InetAddress, ServerSocket, Socket, SocketException }
import ch.ethz.ssh2.crypto.dh.DhExchange
import java.math.BigInteger
import java.security.SecureRandom


object SSHClientSample {
  val CLIENT_VERSION = "SSH-2.0-Sample"
  def using[A <% { def close():Unit }](s: A)(f: A=>Any) {
      try f(s) finally s.close()
  }
  def main(args: Array[String]) = {
    val ia = InetAddress.getByName("localhost")
    using(new Socket(ia, 22)) { socket =>
      using(socket.getOutputStream) { out =>
        using(socket.getInputStream) { in =>

          //TODO: あとでリファクタリング

          //version文字列の交換
          sendVersionString(out, CLIENT_VERSION)
          val serverVersion = recvVersionString(in)
          println("client SSH version: " + CLIENT_VERSION)
          println("server SSH version: " + serverVersion)

          //以後はSSHのパケットのやりとり
          //まだ暗号化されていない
          val rawTransport = new UnencryptedTransport(in, out, new TransportMessageParser)

          val serverKexinit = rawTransport.recvMessage()
          println(serverKexinit)
          assert(serverKexinit.isInstanceOf[Kexinit])

          val clientKexinit = TransportMessageMaker.makeKexinit(
            List("diffie-hellman-group1-sha1"),
            List("ssh-rsa"),
            List("aes128-ctr"), List("aes128-ctr"),
            List("hmac-sha1"), List("hmac-sha1"),
            List("none"), List("none"),
            List(), List(), false)
          rawTransport.sendMessage(clientKexinit)


          val dhTransport = new UnencryptedTransport(in, out, new DhExchangeMessageParser)
          val dhx = new DhExchange
          dhx.init(1, new SecureRandom);
          val kexdhInit = DhExchangeMessageMaker.makeKexdhInit(dhx.getE())
          dhTransport.sendMessage(kexdhInit)

          val kexDhReply = dhTransport.recvMessage()
//          println(kexDhReply)
          assert(kexDhReply.isInstanceOf[KexdhReply])

        }
      }
    }
  }

  private def sendVersionString(out: OutputStream, clientVersion: String) {
    out.write((clientVersion+ "\r\n").getBytes)
  }


  private def recvVersionString(in :InputStream) : String = {
    val reader = new BufferedReader(new InputStreamReader(in))
    val serverString = reader.readLine
    serverString
  }

}

