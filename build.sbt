import AssemblyKeys._ 

name := "SSH client sample"

organization := "org.unixuser"

version := "1.0"

scalaVersion := "2.9.1"

libraryDependencies ++= Seq(
   "org.scalatest" %% "scalatest" % "1.6.1"
  ,"ch.ethz.ganymed" % "ganymed-ssh2" % "build210"
)

scalacOptions ++= Seq( "-deprecation",  "-unchecked" )


seq(assemblySettings: _*)

jarName in assembly := "SSH-client-sample.jar"
