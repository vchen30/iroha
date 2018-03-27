#!/usr/bin/env groovy

def uploadArtifacts(filePaths=[],artifactServers=['54.76.154.71'], agentType='Linux', platform='x86_64') {
  def uploadPath = sprintf('/files/iroha/%1$s/%2$s/%3$s', [agentType.toLowerCase(), platform.toLowerCase(), env.BRANCH_NAME])
  def shaSumBinary = 'sha256sum'
  def md5SumBinary = 'md5sum'
  if (agentType == 'MacOS') {
    shaSumBinary = 'shasum -a 256'
    md5SumBinary = 'md5 -r'
  }
  filePaths.each {
    sh "echo put ${it} $uploadPath >> \$(pwd)/batch.txt;"
    sh "$shaSumBinary ${it} | cut -d' ' -f1 > \$(pwd)/\$(basename ${it}).sha256"
    sh "$md5SumBinary ${it} | cut -d' ' -f1 > \$(pwd)/\$(basename ${it}).md5"
    sh "echo put \$(pwd)/\$(basename ${it}).sha256 $uploadPath >> \$(pwd)/batch.txt;"
    sh "echo put \$(pwd)/\$(basename ${it}).md5 $uploadPath >> \$(pwd)/batch.txt;"
  }
  sshagent(['jenkins-artifact']) {
    sh "ssh-agent"
    artifactServers.each {
      sh "sftp -b \$(pwd)/batch.txt jenkins@${it}"
    }
  }
}

return this