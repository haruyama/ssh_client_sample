import sbt._

class MyProject(info: ProjectInfo) extends DefaultProject(info) {
    val scalaTest = "org.scalatest" % "scalatest_2.9.0" % "1.6.1"
}
