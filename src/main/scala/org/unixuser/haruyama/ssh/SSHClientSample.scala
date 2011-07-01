package org.unixuser.haruyama.ssh

import org.unixuser.haruyama.ssh.transport._
import java.io._
import java.net.{ InetAddress, ServerSocket, Socket, SocketException }
import java.math.BigInteger
import java.security.SecureRandom
import ch.ethz.ssh2.crypto.dh.DhExchange
import ch.ethz.ssh2.signature.RSAPublicKey
import ch.ethz.ssh2.signature.RSASHA1Verify
import ch.ethz.ssh2.signature.RSASignature
import ch.ethz.ssh2.crypto.KeyMaterial
import ch.ethz.ssh2.crypto.cipher.BlockCipher
import ch.ethz.ssh2.crypto.cipher.BlockCipherFactory
import ch.ethz.ssh2.crypto.digest.MAC



object SSHClientSample {
  val CLIENT_VERSION = "SSH-2.0-Sample"
  private def using[A <% { def close():Unit }](s: A)(f: A=>Any) {
      try f(s) finally s.close()
  }

  private def exchangeVersion(in: InputStream, out: OutputStream, clientVersion : String) = {
    //version文字列の交換
    //CR LF 集団の文字列でやりとりされる
    sendVersionString(out, clientVersion)
    val serverVersion = recvVersionString(in)
    println("client SSH version: " + clientVersion)
    println("server SSH version: " + serverVersion)
    //version のすり合わせは省略する
    serverVersion
  }



  private def negotiateAlgorithm(transport : Transport) = {

    //以後はSSHのパケットでやりとりされる

    //サーバから KEXINIT メッセージを受け取る
    val serverKexinit = transport.recvMessage().asInstanceOf[Kexinit]

    //クライアントから KEXINIT メッセージを送る
    //この実装はアルゴリズムをそれぞれ1つのみサポートし，
    //アルゴリズムに依存した実装を行なう
    val clientKexinit = TransportMessageMaker.makeKexinit(
      List("diffie-hellman-group1-sha1"), List("ssh-rsa"),
      List("aes128-ctr"), List("aes128-ctr"),
      List("hmac-sha1"), List("hmac-sha1"),
      List("none"), List("none"),
      List(), List(), false)
    transport.sendMessage(clientKexinit)

    //交換ハッシュ H の計算に必要なのでこれらを返す
    (clientKexinit, serverKexinit)
  }

  private def exchangeKeys(transport : Transport, clientVersion: String, serverVersion: String, clientKexinit : Kexinit, serverKexinit: Kexinit) = {

    //diffie-hellman-group1-sha1 鍵交換法を行なう準備
    val dhx = new DhExchange
    dhx.init(1, new SecureRandom);

    // KEXDH_INIT メッセージを送信
    val kexdhInit = DhExchangeMessageMaker.makeKexdhInit(dhx.getE())
    transport.sendMessage(kexdhInit)

    // KEYDH_REPLY メッセージを受信
    val kexDhReply = transport.recvMessage().asInstanceOf[KexdhReply]

    // 本来は KEYDH_REPLY にホスト公開鍵をローカルなデータベースなどで検証し
    // 接続先ホストを認証しなければならない．ここでは省略する

    // 交換ハッシュ H を計算
    dhx.setF(kexDhReply.f.value)
    val h = dhx.calculateH(clientVersion.getBytes, serverVersion.getBytes, clientKexinit.toBytes,
      serverKexinit.toBytes, kexDhReply.hostKey.value)

    // KEYDH_REPLY 中に H の署名がついている．これをホスト公開鍵で検証
    val rs = RSASHA1Verify.decodeSSHRSASignature(kexDhReply.sigOfH.value)
    val rpk = RSASHA1Verify.decodeSSHRSAPublicKey(kexDhReply.hostKey.value)
    if (!RSASHA1Verify.verifySignature(h, rs, rpk)) new RuntimeException("RSA Key is not verified")

    // 交換ハッシュ H と 共有の秘密 K を返す
    (h, dhx.getK)
  }


  private def createCiphersAndMacs(oldId: Option[Array[Byte]], h : Array[Byte], k : BigInteger) {
    val sessionId = new Array[Byte](h.length)
    oldId match {
      case Some(oid) => oid.copyToArray(sessionId, 0)
      case None      => h.copyToArray(sessionId, 0)
    }

    // 暗号とMACは決め打ちなのでサイズも決め打ち
    val km = KeyMaterial.create("SHA1", h, k, sessionId, 16, 16, 20, 16, 16, 20)
    val cipherC2S = BlockCipherFactory.createCipher("aes128-ctr", true, km.enc_key_client_to_server, km.initial_iv_client_to_server)
    val cipherS2C = BlockCipherFactory.createCipher("aes128-ctr", true, km.enc_key_server_to_client, km.initial_iv_server_to_client)
    val macC2S    = new MAC("hmac-sha1", km.integrity_key_client_to_server)
    val macS2C    = new MAC("hmac-sha1", km.integrity_key_server_to_client)

    (cipherC2S, cipherS2C, macC2S, macS2C)
  }

  def main(args: Array[String]) = {
    val ia = InetAddress.getByName("localhost")
    using(new Socket(ia, 22)) { socket =>
      using(socket.getOutputStream) { out =>
        using(socket.getInputStream) { in =>

          val serverVersion = exchangeVersion(in, out, CLIENT_VERSION)

          val (clientKexinit, serverKexinit) = negotiateAlgorithm(new UnencryptedTransport(in, out, new TransportMessageParser))

          val (h, k) = exchangeKeys(new UnencryptedTransport(in, out, new DhExchangeMessageParser), CLIENT_VERSION, serverVersion,
            clientKexinit, serverKexinit)
        }
      }
    }
  }

  private def sendVersionString(out: OutputStream, clientVersion: String) {
    out.write((clientVersion+ "\r\n").getBytes)
  }


  private def recvVersionString(in :InputStream) : String = {
    val reader = new BufferedReader(new InputStreamReader(in))
    var serverString = ""
    //"SSH-"  で開始しない文字列は無視する
    do {
      serverString = reader.readLine
    } while (!serverString.startsWith("SSH-"))
    serverString
  }
}

