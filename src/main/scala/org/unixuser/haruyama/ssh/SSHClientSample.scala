package org.unixuser.haruyama.ssh

import org.unixuser.haruyama.ssh.transport._
import org.unixuser.haruyama.ssh.userauth._
import org.unixuser.haruyama.ssh.connection._
//import org.unixuser.haruyama.ssh.channel._
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

  private def exchangeNewkeys(transport: Transport) {
    //NEWKEYS メッセージを交換
    //新しい鍵になったことを知らせあう(鍵自体は送らない)
    val serverNewkeys = transport.recvMessage().asInstanceOf[Newkeys]
    transport.sendMessage(TransportMessageMaker.makeNewkeys)
  }

  private def userauthPassword(transport: Transport, user: String, pass: String) {

    transport.sendMessage(TransportMessageMaker.makeServiceRequest("ssh-userauth"))
    val serviceRequestResult = transport.recvMessage().asInstanceOf[ServiceAccept]


    transport.sendMessage(UserauthMessageMaker.makeUserauthRequestPassword(user, pass))
    val userauthResult = transport.recvMessage().asInstanceOf[UserauthSuccess]
  }

  private def execCommand(transport: Transport, command : String) {
    val senderChannel = 0
    var windowSize = 32678
    val maximumPacketSize = 32678
    transport.sendMessage(ConnectionMessageMaker.makeChannelOpenSession(senderChannel, windowSize, maximumPacketSize))
    val channelOpenConfirmation = transport.recvMessage().asInstanceOf[ChannelOpenConfirmation]
//    println(channelOpenConfirmation)
    val recipientChannel = channelOpenConfirmation.recipientChannel.value

    transport.sendMessage(ConnectionMessageMaker.makeChannelRequestExec(recipientChannel, command))

    val channelWindowAdjust = transport.recvMessage().asInstanceOf[ChannelWindowAdjust]
//    println(channelWindowAdjust)

    val channelData =  transport.recvMessage().asInstanceOf[ChannelData]
    println(new String(channelData.data.value))

    val channelEof = transport.recvMessage().asInstanceOf[ChannelEof]
//    println(channelEof)


    val channelExitStatus = transport.recvMessage().asInstanceOf[ChannelRequestExitStatus]
//    println(channelExitStatus)
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

          val (clientKexinit, serverKexinit) = negotiateAlgorithm(transportManager.transport)

          transportManager.setParser(new DhExchangeMessageParser)
          val (h, k) = exchangeKeys(transportManager.transport, CLIENT_VERSION, serverVersion,
            clientKexinit, serverKexinit)

          exchangeNewkeys(transportManager.transport)

          transportManager.changeKey(h, k)

          transportManager.setParser(new UserauthMessageParser)
          userauthPassword(transportManager.transport, user, pass)

          transportManager.setParser(new ConnectionMessageParser)
          execCommand(transportManager.transport, command)
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

