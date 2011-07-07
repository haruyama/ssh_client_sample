package org.unixuser.haruyama.ssh

import org.unixuser.haruyama.ssh.transport._
import org.unixuser.haruyama.ssh.userauth._
import org.unixuser.haruyama.ssh.connection._
//import org.unixuser.haruyama.ssh.channel._

import scala.actors._

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
//    println("client SSH version: " + clientVersion)
//    println("server SSH version: " + serverVersion)
    //version のすり合わせは省略する
    serverVersion
  }



  private def negotiateAlgorithm(transport : TransportManager) = {

    //以後はSSHのパケットでやりとりされる

    //サーバから KEXINIT メッセージを受け取る
    val serverKexinit = transport.recvMessage().asInstanceOf[Kexinit]

    //クライアントから KEXINIT メッセージを送る
    //この実装はアルゴリズムをそれぞれ1つのみサポートし，
    //アルゴリズムに依存した実装を行なう
    val clientKexinit = TransportMessageBuilder.buildKexinit(
      List("diffie-hellman-group1-sha1"), List("ssh-rsa"),
      List("aes128-ctr"), List("aes128-ctr"),
      List("hmac-sha1"), List("hmac-sha1"),
      List("none"), List("none"),
      List(), List(), false)
    transport.sendMessage(clientKexinit)

    //交換ハッシュ H の計算に必要なのでこれらを返す
    (clientKexinit, serverKexinit)
  }

  private def exchangeKeys(transport : TransportManager, clientVersion: String, serverVersion: String, clientKexinit : Kexinit, serverKexinit: Kexinit) = {

    //diffie-hellman-group1-sha1 鍵交換法を行なう準備
    val dhx = new DhExchange
    dhx.init(1, new SecureRandom);

    // KEXDH_INIT メッセージを送信
    val kexdhInit = DhExchangeMessageBuilder.buildKexdhInit(dhx.getE())
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

  private def exchangeNewkeys(transport: TransportManager) {
    //NEWKEYS メッセージを交換
    //新しい鍵になったことを知らせあう(鍵自体は送らない)
    val serverNewkeys = transport.recvMessage().asInstanceOf[Newkeys]
    transport.sendMessage(TransportMessageBuilder.buildNewkeys)
  }

  private def userauthPassword(transport: TransportManager, user: String, pass: String) {

    transport.sendMessage(TransportMessageBuilder.buildServiceRequest("ssh-userauth"))
    val serviceRequestResult = transport.recvMessage().asInstanceOf[ServiceAccept]


    transport.sendMessage(UserauthMessageBuilder.buildUserauthRequestPassword(user, pass))
    val userauthResult = transport.recvMessage()

    userauthResult match {
      case success : UserauthSuccess =>
      case UserauthFailure(id, authentications, partialSuccess) =>
        println("Userauth failed")
        println(authentications)
        throw new RuntimeException("Uearauth failed")
    }
  }

  private def execCommand(transport: TransportManager, command : String) {
    val senderChannel = 0
    var windowSize = 32678
    val maximumPacketSize = 32678
    transport.sendMessage(ConnectionMessageBuilder.buildChannelOpenSession(senderChannel, windowSize, maximumPacketSize))
    val channelOpenConfirmation = transport.recvMessage().asInstanceOf[ChannelOpenConfirmation]
//    println(channelOpenConfirmation)
    val recipientChannel = channelOpenConfirmation.recipientChannel.value

    transport.sendMessage(ConnectionMessageBuilder.buildChannelRequestExec(recipientChannel, command))

    val channelWindowAdjust = transport.recvMessage().asInstanceOf[ChannelWindowAdjust]

    val channelData =  transport.recvMessage().asInstanceOf[ChannelData]
    println(new String(channelData.data.value))

    val channelEof = transport.recvMessage().asInstanceOf[ChannelEof]

    val channelExitStatus = transport.recvMessage().asInstanceOf[ChannelRequestExitStatus]

    transport.sendMessage(ConnectionMessageBuilder.buildChannelClose(recipientChannel))

    val channelClose = transport.recvMessage().asInstanceOf[ChannelClose]
  }

  def disconnect(transport : TransportManager) {
    transport.sendMessage(TransportMessageBuilder.buildDisconnect())
  }

  def main(args: Array[String]) = {

    if (args.length < 5) {
      throw new IllegalArgumentException("please run 'scala SSHClientSample [host] [port] [user] [pass] [command]'")
    }
    val host = args(0)
    val port = args(1).toInt
    val user = args(2)
    val pass = args(3)
    val command = args(4)


    val ia = InetAddress.getByName(host)
    using(new Socket(ia, port)) { socket =>
      using(socket.getOutputStream) { out =>
        using(socket.getInputStream) { in =>

          val serverVersion = exchangeVersion(in, out, CLIENT_VERSION)
          val transportManager = new TransportManager(in, out)

          val (clientKexinit, serverKexinit) = negotiateAlgorithm(transportManager)

          transportManager.setOverlayParser(new DhExchangeMessageParser)
          val (h, k) = exchangeKeys(transportManager, CLIENT_VERSION, serverVersion,
            clientKexinit, serverKexinit)

          transportManager.clearOverlayParser
          exchangeNewkeys(transportManager)

          transportManager.changeKey(h, k)

          transportManager.setOverlayParser(new UserauthMessageParser)
          userauthPassword(transportManager, user, pass)

          transportManager.setOverlayParser(new ConnectionMessageParser)
          execCommand(transportManager, command)

          disconnect(transportManager)
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

