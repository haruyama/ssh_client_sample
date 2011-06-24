class UInt32(v: Long) {
  assert(v >= 0)
  assert(v < 4294967296L)
  val value = v
  def toByteArray : Array[Byte] = {
    val byteArray = new Array[Byte](4)
    byteArray(0) = ((value >> 24) & 0xff).toByte
    byteArray(1) = ((value >> 16) & 0xff).toByte
    byteArray(2) = ((value >> 8) & 0xff).toByte
    byteArray(3) = (value & 0xff).toByte
    byteArray
  }

}

object UInt32 {
  def parse(message: Array[Byte], offset: Int) : (UInt32, Int) = {
    val value = ((message(offset) & 0xff).toLong << 24) + ((message(offset + 1) & 0xff).toLong << 16) + ((message(offset + 2) & 0xff).toLong <<
      8) + (message(offset + 3) & 0xff).toLong
    (new UInt32(value), offset + 4)
  }
}
