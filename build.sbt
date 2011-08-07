name := "SSH client sample"

organization := "org.unixuser"

version := "1.0"

scalaVersion := "2.9.0-1"

libraryDependencies ++= Seq(
   "org.scalatest" %% "scalatest" % "1.6.1"
  ,"ch.ethz.ganymed" % "ganymed-ssh2" % "build210"
)

scalacOptions ++= Seq( "-deprecation",  "-unchecked" )
