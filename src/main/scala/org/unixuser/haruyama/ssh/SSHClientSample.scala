package org.unixuser.haruyama.ssh

import org.unixuser.haruyama.ssh.transport._
import org.unixuser.haruyama.ssh.userauth._
import org.unixuser.haruyama.ssh.connection._

import java.io._
import java.net.{ InetAddress, ServerSocket, Socket, SocketException }
import java.math.BigInteger
import java.security.SecureRandom

import ch.ethz.ssh2.crypto.dh.DhExchange
import ch.ethz.ssh2.signature.{RSAPublicKey, RSASHA1Verify, RSASignature}
import ch.ethz.ssh2.crypto.KeyMaterial
import ch.ethz.ssh2.crypto.cipher.{BlockCipher, BlockCipherFactory}
import ch.ethz.ssh2.crypto.digest.MAC

object SSHClientSample {

  val CLIENT_VERSION = "SSH-2.0-Sample"

  private def using[A <% { def close():Unit }](s: A)(f: A=>Any) {
    try f(s) finally s.close()
  }

  private def sendVersionString(out: OutputStream, clientVersion: String) {
    out.write((clientVersion+ "\r\n").getBytes)
  }

  private def recvVersionString(in:InputStream): String = {
    val reader = new BufferedReader(new InputStreamReader(in))
    var serverString = ""
    //"SSH-"  で開始しない文字列は無視する
    do {
      serverString = reader.readLine
    } while (!serverString.startsWith("SSH-"))
    serverString
  }

  private def exchangeVersion(in: InputStream, out: OutputStream, clientVersion: String) = {
    //バージョン文字列の交換
    //CR LF 区切りの文字列でやりとりする

    //クライアントからバージョン文字列を送る
    sendVersionString(out, clientVersion)

    //サーバからバージョン文字列を受け取る
    val serverVersion = recvVersionString(in)

    //version のすり合わせは省略している

    //クライアントとサーバのバージョン文字列は鍵の生成で利用するので
    //サーバのバージョン文字列を返す
    serverVersion
  }

  private def negotiateAlgorithm(transportManager: TransportManager) = {
    //以後はSSHのパケットでやりとりされる

    //クライアントから KEXINIT メッセージを送る
    //この実装はアルゴリズムをそれぞれ1つのみサポートし，
    //アルゴリズムに依存した実装を行なう
    val clientKexinit = TransportMessageBuilder.buildKexinit(
      List("diffie-hellman-group1-sha1"), List("ssh-rsa"),
      List("aes128-ctr"), List("aes128-ctr"),
      List("hmac-sha1"), List("hmac-sha1"),
      List("none"), List("none"),
      List(), List(), false)
    transportManager.sendMessage(clientKexinit)

    //サーバから KEXINIT メッセージを受け取る
    val serverKexinit = transportManager.recvMessage().asInstanceOf[Kexinit]

    //アルゴリズムのネゴシエーションが本来は必要
    //この実装では, クライアント側が1つずつ指定したアルゴリズムが
    //受け入れられたと仮定して先に進む

    //クライアントとサーバのKEXINITメッセージが鍵の生成に必要なので
    //以下を返す
    (clientKexinit, serverKexinit)
  }

  private def exchangeKeys(transportManager: TransportManager, clientVersion: String, serverVersion: String, clientKexinit: Kexinit, serverKexinit: Kexinit) = {

    //ch.ethz.ssh2.crypto.dh.DhExchange を利用して
    //diffie-hellman-group1-sha1 鍵交換法を行なう準備をする
    val dhx = new DhExchange
    dhx.init(1, new SecureRandom);

    // SSH_MSG_KEXDH_INIT メッセージを送信する
    val kexdhInit = DhExchangeMessageBuilder.buildKexdhInit(dhx.getE())
    transportManager.sendMessage(kexdhInit)

    // SSH_MSG_KEYDH_REPLY メッセージを受信する
    val kexDhReply = transportManager.recvMessage().asInstanceOf[KexdhReply]

    // SSH_MSG_KEYDH_REPLY にホスト公開鍵をローカルなデータベースなどで検証し
    // 接続先ホストを認証しなければならない．ここでは省略する

    // 交換ハッシュ H を計算する
    dhx.setF(kexDhReply.f.value)
    val h = dhx.calculateH(clientVersion.getBytes, serverVersion.getBytes, clientKexinit.toBytes,
      serverKexinit.toBytes, kexDhReply.hostKey.value)

    // SSH_MSG_KEYDH_REPLY 中に H の署名がついている．これをホスト公開鍵で検証する
    val rs = RSASHA1Verify.decodeSSHRSASignature(kexDhReply.sigOfH.value)
    val rpk = RSASHA1Verify.decodeSSHRSAPublicKey(kexDhReply.hostKey.value)
    if (!RSASHA1Verify.verifySignature(h, rs, rpk)) new RuntimeException("RSA Key is not verified")

    // 交換ハッシュ H と 共有の秘密 K を返す
    (h, dhx.getK)
  }

  private def exchangeNewkeys(transportManager: TransportManager) {
    // SSH_MSG_NEWKEYS メッセージを交換する
    // 新しい鍵になったことを知らせあう(当然ながら鍵自体は送らない)

    // SSH_MSG_NEWKEYS を送信する
    transportManager.sendMessage(TransportMessageBuilder.buildNewkeys)

    // SSH_MSG_NEWKEYS を受信する
    val serverNewkeys = transportManager.recvMessage().asInstanceOf[Newkeys]
  }

  private def userauthPassword(transportManager: TransportManager, user: String, pass: String) {

    // SSH_MSG_SERVICE_REQUEST で "ssh-userauth" サービスをクライアントからサーバに要求する
    transportManager.sendMessage(TransportMessageBuilder.buildServiceRequest("ssh-userauth"))

    // SSH_MSG_SERVICE_ACCEPT を受信する
    val serviceRequestResult = transportManager.recvMessage().asInstanceOf[ServiceAccept]

    // SSH_MSG_USERAUTH_REQUEST で "password" 認証を要求する
    transportManager.sendMessage(UserauthMessageBuilder.buildUserauthRequestPassword(user, pass))

    // SSH_MSG_USERAUTH_SUCCESS か SSH_MSG_USERAUTH_FAILURE を受信する
    val userauthResult = transportManager.recvMessage()

    userauthResult match {
      case success: UserauthSuccess =>
      case UserauthFailure(id, authentications, partialSuccess) =>
        println("Userauth failed")
        println(authentications)
        throw new RuntimeException("Uearauth failed")
    }
  }

  private def execCommand(transportManager: TransportManager, command: String) {

    val senderChannel = 0
    var windowSize = 32678
    val maximumPacketSize = 32678
    transportManager.sendMessage(ConnectionMessageBuilder.buildChannelOpenSession(senderChannel, windowSize, maximumPacketSize))
    val channelOpenConfirmation = transportManager.recvMessage().asInstanceOf[ChannelOpenConfirmation]
    //    println(channelOpenConfirmation)
    val recipientChannel = channelOpenConfirmation.recipientChannel.value

    transportManager.sendMessage(ConnectionMessageBuilder.buildChannelRequestExec(recipientChannel, command))

    val channelWindowAdjust = transportManager.recvMessage().asInstanceOf[ChannelWindowAdjust]

    val channelData =  transportManager.recvMessage().asInstanceOf[ChannelData]
    println(new String(channelData.data.value))

    val channelEof = transportManager.recvMessage().asInstanceOf[ChannelEof]

    val channelExitStatus = transportManager.recvMessage().asInstanceOf[ChannelRequestExitStatus]

    transportManager.sendMessage(ConnectionMessageBuilder.buildChannelClose(recipientChannel))

    val channelClose = transportManager.recvMessage().asInstanceOf[ChannelClose]
  }

  private def ssh(in: InputStream, out: OutputStream, user: String, pass: String, command: String) {

    val serverVersion = exchangeVersion(in, out, CLIENT_VERSION)
    val transportManager = new TransportManager(in, out)

    val (clientKexinit, serverKexinit) = negotiateAlgorithm(transportManager)

    transportManager.useDhContext
    val (h, k) = exchangeKeys(transportManager, CLIENT_VERSION, serverVersion,
      clientKexinit, serverKexinit)

    exchangeNewkeys(transportManager)

    transportManager.changeKey(h, k)

    transportManager.useUserauthContext
    userauthPassword(transportManager, user, pass)

    transportManager.useConnectionContext
    execCommand(transportManager, command)
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

          ssh(in, out, user, pass, command)

        }
      }
    }
  }
}

